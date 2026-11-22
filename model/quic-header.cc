/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *
 */

#include <stdint.h>
#include <iostream>
#include "quic-header.h"
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicHeader");

NS_OBJECT_ENSURE_REGISTERED (QuicHeader);

QuicHeader::QuicHeader ()
  : m_form (SHORT),
  m_c (false),
  m_spinBit (false),
  m_k (PHASE_ZERO),
  m_type (0),
  m_connectionId (0),
  m_packetNumber (0),
  m_version (0)
{
}


QuicHeader::~QuicHeader ()
{
}

std::string
QuicHeader::TypeToString () const
{
  static const char* longTypeNames[6] = {
    "Version Negotiation",
    "Initial",
    "Retry",
    "Handshake",
    "0-RTT Protected",
    "None"
  };
  static const char* shortTypeNames[4] = {
    "1 Octet",
    "2 Octets",
    "4 Octets"
  };

  std::string typeDescription = "";

  if (IsLong ())
    {
      typeDescription.append (longTypeNames[m_type]);
    }
  else
    {
      typeDescription.append (shortTypeNames[m_type]);
    }
  return typeDescription;
}

TypeId
QuicHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicHeader")
    .SetParent<Header> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicHeader> ()
  ;
  return tid;
}

TypeId
QuicHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
QuicHeader::GetSerializedSize (void) const
{
  NS_ASSERT (m_type != NONE or m_form == SHORT);

  uint32_t serializesSize = CalculateHeaderLength ();
  NS_LOG_INFO ("Serialized Size " << serializesSize);

  return serializesSize;
}

uint32_t
QuicHeader::CalculateHeaderLength () const
{
  uint32_t len;

  if (IsLong ())
    {
      if (IsVersionNegotiation ())
        {
          len = 8 + 32 + 8 + 64 + 8;          // first_byte + version + DCIL + DCID + SCIL = 15 bytes
        }
      else
        {
          len = 8 + 32 + 8 + 64 + 8 + 32;     // + packetNumber = 19 bytes
        }
    }
  else
    {
      len = 8 + 64 * HasConnectionId () + GetPacketNumLen ();
    }
  return len / 8;
}

uint32_t
QuicHeader::GetPacketNumLen () const
{
  if (IsLong ())
    {
      return 32;
    }
  else
    {
      switch (m_type)
        {
        case ONE_OCTECT:
          {
            return 8;
            break;
          }
        case TWO_OCTECTS:
          {
            return 16;
            break;
          }
        case FOUR_OCTECTS:
          {
            return 32;
            break;
          }
        }
    }
  NS_FATAL_ERROR ("Invalid conditions");
  return 0;
}

void
QuicHeader::Serialize (Buffer::Iterator start) const
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_type != NONE or m_form == SHORT);
  NS_LOG_INFO ("Serialize::Serialized Size " << CalculateHeaderLength ());

  Buffer::Iterator i = start;

  if (m_form)
    {
      // RFC 9000 §17.2 Long Header first byte encoding:
      // VERSION_NEGOTIATION: 0x80 (Fixed Bit = 0, §17.2.1)
      // Others: 0xC0 | (type << 4), where type: INITIAL=0, 0-RTT=1, HANDSHAKE=2, RETRY=3
      // ns-3 TypeLong_t: VERSION_NEGOTIATION=0, INITIAL=1, RETRY=2, HANDSHAKE=3, ZRTT_PROTECTED=4
      uint8_t t;
      if (IsVersionNegotiation ())
        {
          // RFC 9000 s17.2.1: the bits after the form bit are unused; the Fixed Bit is set, as RFC 9287 asks
          t = 0xC0;
        }
      else
        {
          // Map ns-3 types to RFC 9000 bits [4:5]: INITIAL=0x00,ZRTT=0x10,HANDSHAKE=0x20,RETRY=0x30
          // The two low bits are the packet number length minus one: this module always writes 4 bytes (0x03)
          static const uint8_t ns3ToRfcTypeBits[5] = { 0x00, 0x00, 0x30, 0x20, 0x10 };
          t = 0xC0 | ns3ToRfcTypeBits[m_type & 0x07] | 0x03;
        }
      i.WriteU8 (t);
      // RFC 9000 s17.2.1: a Version Negotiation packet is the one whose version is 0
      i.WriteHtonU32 (IsVersionNegotiation () ? 0 : m_version);
      i.WriteU8 (8);                        // DCIL = 8 bytes
      i.WriteHtonU64 (m_connectionId);      // DCID (8 bytes)
      i.WriteU8 (0);                        // SCIL = 0 (no source CID)
      if (!IsVersionNegotiation ())
        {
          i.WriteHtonU32 (m_packetNumber.GetValue ());
        }
    }
  else
    {
      // RFC 9000 s17.3.1: 0 | Fixed Bit (1) | Spin Bit | Reserved (00) | Key Phase | Packet Number Length (2).
      // The connection id is always written (8 bytes) unless OmitConnectionId was negotiated, which this module
      // flags with the first reserved bit: a header with the id is a valid RFC 9000 short header
      uint8_t pnBits = (m_type == FOUR_OCTECTS) ? 0x3 : m_type;      // 00: 1 byte, 01: 2 bytes, 11: 4 bytes
      uint8_t t = 0x40 | (m_spinBit << 5) | (m_k << 2) | pnBits | (m_c ? 0x00 : 0x08);
      i.WriteU8 (t);

      if (m_c)
        {
          i.WriteHtonU64 (m_connectionId);
        }

      switch (m_type)
        {
        case ONE_OCTECT:
          i.WriteU8 ((uint8_t)m_packetNumber.GetValue ());
          break;
        case TWO_OCTECTS:
          i.WriteHtonU16 ((uint16_t)m_packetNumber.GetValue ());
          break;
        case FOUR_OCTECTS:
          i.WriteHtonU32 ((uint32_t)m_packetNumber.GetValue ());
          break;
        }
    }
}

uint32_t
QuicHeader::Deserialize (Buffer::Iterator start)
{
  NS_LOG_FUNCTION (this);

  Buffer::Iterator i = start;

  uint8_t t = i.ReadU8 ();

  m_form = (t & 0x80) >> 7;

  if (IsShort ())
    {
      // RFC 9000 s17.3.1 (see Serialize)
      m_c = !(t & 0x08);
      m_spinBit = (t & 0x20) >> 5;
      m_k = (t & 0x04) >> 2;
      static const uint8_t pnLength[4] = { ONE_OCTECT, TWO_OCTECTS, FOUR_OCTECTS, FOUR_OCTECTS };
      SetTypeByte (pnLength[t & 0x03]);
    }
  else
    {
      // RFC 9000 s17.2: the version follows the first byte; version 0 marks a Version Negotiation packet,
      // otherwise bits [5:4] encode the type: 00=INITIAL,01=0-RTT,10=HANDSHAKE,11=RETRY
      uint32_t version = i.ReadNtohU32 ();
      if (version == 0)
        {
          SetTypeByte (VERSION_NEGOTIATION);
        }
      else
        {
          static const uint8_t rfcToNs3Type[4] = { INITIAL, ZRTT_PROTECTED, HANDSHAKE, RETRY };
          SetTypeByte (rfcToNs3Type[(t >> 4) & 0x03]);
        }
      SetVersion (version);
    }
  NS_ASSERT (m_type != NONE or m_form == SHORT);

  if (IsLong ())
    {
      // RFC 9000 Long Header: version (read above) | DCIL | DCID | SCIL | SCID | ...
      uint8_t dcil = i.ReadU8 ();
      if (dcil == 8)
        {
          SetConnectionID (i.ReadNtohU64 ());
        }
      else
        {
          for (uint8_t k = 0; k < dcil; k++) { i.ReadU8 (); }
        }
      uint8_t scil = i.ReadU8 ();
      for (uint8_t k = 0; k < scil; k++) { i.ReadU8 (); }
      if (!IsVersionNegotiation ())
        {
          SetPacketNumber (SequenceNumber32 (i.ReadNtohU32 ()));
        }
    }
  else
    {
      if (m_c)
        {
          SetConnectionID (i.ReadNtohU64 ());
        }
      switch (m_type)
        {
        case ONE_OCTECT:
          SetPacketNumber (SequenceNumber32 (i.ReadU8 ()));
          break;
        case TWO_OCTECTS:
          SetPacketNumber (SequenceNumber32 (i.ReadNtohU16 ()));
          break;
        case FOUR_OCTECTS:
          SetPacketNumber (SequenceNumber32 (i.ReadNtohU32 ()));
          break;
        }
    }

  NS_LOG_INFO ("Deserialize::Serialized Size " << CalculateHeaderLength ());

  return GetSerializedSize ();
}

void
QuicHeader::Print (std::ostream &os) const
{
  NS_ASSERT (m_type != NONE or m_form == SHORT);

  os << "|" << m_form << "|";

  if (IsShort ())
    {
      os << m_c << "|" << m_spinBit << "|" << m_k << "|" << "1|0|";
    }

  os << TypeToString () << "|\n|";

  if (HasConnectionId ())
    {
      os << "ConnectionID " << m_connectionId << "|\n|";
    }
  if (IsShort ())
    {
      os << "PacketNumber " << m_packetNumber << "|\n";
    }
  else
    {
      os << "Version " << (uint64_t)m_version << "|\n";
      os << "PacketNumber " << m_packetNumber << "|\n|";
    }

}

QuicHeader
QuicHeader::CreateInitial (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create Initial Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::INITIAL);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}


QuicHeader
QuicHeader::CreateRetry (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create Retry Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::RETRY);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}

QuicHeader
QuicHeader::CreateHandshake (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create Handshake Helper called ");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::HANDSHAKE);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}

QuicHeader
QuicHeader::Create0RTT (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create 0RTT Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::ZRTT_PROTECTED);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}

QuicHeader
QuicHeader::CreateShort (uint64_t connectionId, SequenceNumber32 packetNumber, bool connectionIdFlag, bool keyPhaseBit, bool spinBit)
{
  NS_LOG_INFO ("Create Short Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::SHORT);
  head.SetKeyPhaseBit (keyPhaseBit);
  head.SetSpinBit (spinBit);
  head.SetPacketNumber (packetNumber);

  if (connectionIdFlag)
    {
      head.SetConnectionID (connectionId);
    }

  return head;
}

QuicHeader
QuicHeader::CreateVersionNegotiation (uint64_t connectionId, uint32_t version, std::vector<uint32_t>& supportedVersions)
{
  NS_LOG_INFO ("Create Version Negotiation Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::VERSION_NEGOTIATION);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);

//	TODO: SetVersions(m)
//	head.SetVersions(m_supportedVersions);
//
//   uint8_t *buffer = new uint8_t[4 * m_supportedVersions.size()];
//
//    for (uint8_t i = 0; i < (uint8_t) m_supportedVersions.size(); i++) {
//
//	    buffer[4*i] = (m_supportedVersions[i]) ;
//	    buffer[4*i+1] = (m_supportedVersions[i] >> 8);
//	    buffer[4*i+2] = (m_supportedVersions[i] >> 16);
//	    buffer[4*i+3] = (m_supportedVersions[i] >> 24);
//
//    }
//
//    Ptr<Packet> payload = Create<Packet> (buffer, 4 * m_supportedVersions.size());

  return head;
}

uint8_t
QuicHeader::GetTypeByte () const
{
  return m_type;
}

void
QuicHeader::SetTypeByte (uint8_t typeByte)
{
  m_type = typeByte;
}

uint8_t
QuicHeader::GetFormat () const
{
  return m_form;
}

void
QuicHeader::SetFormat (bool form)
{
  m_form = form;
}

uint64_t
QuicHeader::GetConnectionId () const
{
  NS_ASSERT (HasConnectionId ());
  return m_connectionId;
}

void
QuicHeader::SetConnectionID (uint64_t connID)
{
  m_connectionId = connID;
  if (IsShort ())
    {
      m_c = true;
    }
}

SequenceNumber32
QuicHeader::GetPacketNumber () const
{
  return m_packetNumber;
}

void
QuicHeader::SetPacketNumber (SequenceNumber32 packNum)
{
  NS_LOG_INFO (packNum);
  m_packetNumber = packNum;
  if (IsShort ())
    {
      if (packNum.GetValue () < 256)
        {
          SetTypeByte (ONE_OCTECT);
        }
      else if (packNum.GetValue () < 65536)
        {
          SetTypeByte (TWO_OCTECTS);
        }
      else
        {
          SetTypeByte (FOUR_OCTECTS);
        }
    }
}

uint32_t
QuicHeader::GetVersion () const
{
  NS_ASSERT (HasVersion ());
  return m_version;
}

void
QuicHeader::SetVersion (uint32_t version)
{
  NS_ASSERT (HasVersion ());
  m_version = version;
}

bool
QuicHeader::GetKeyPhaseBit () const
{
  NS_ASSERT (IsShort ());
  return m_k;
}

void
QuicHeader::SetKeyPhaseBit (bool keyPhaseBit)
{
  NS_ASSERT (IsShort ());
  m_k = keyPhaseBit;
}

bool
QuicHeader::GetSpinBit () const
{
  NS_ASSERT (IsShort ());
  return m_spinBit;
}

void
QuicHeader::SetSpinBit (bool spinBit)
{
  NS_ASSERT (IsShort ());
  m_spinBit = spinBit;
}

bool QuicHeader::IsShort () const
{
  return m_form == SHORT;
}

bool
QuicHeader::IsVersionNegotiation () const
{
  return m_type == VERSION_NEGOTIATION;
}

bool
QuicHeader::IsInitial () const
{
  return m_type == INITIAL;
}

bool
QuicHeader::IsRetry () const
{
  return m_type == RETRY;
}

bool
QuicHeader::IsHandshake () const
{
  return m_type == HANDSHAKE;
}

bool
QuicHeader::IsORTT () const
{
  return m_type == ZRTT_PROTECTED;
}

bool QuicHeader::HasVersion () const
{
  return IsLong ();
}

bool QuicHeader::HasConnectionId () const
{
  return not (IsShort () and m_c == false);
}

bool
operator== (const QuicHeader &lhs, const QuicHeader &rhs)
{
  return (
    lhs.m_form == rhs.m_form
    && lhs.m_c == rhs.m_c
    && lhs.m_spinBit == rhs.m_spinBit
    && lhs.m_k  == rhs.m_k
    && lhs.m_type == rhs.m_type
    && lhs.m_connectionId == rhs.m_connectionId
    && lhs.m_packetNumber == rhs.m_packetNumber
    && lhs.m_version == rhs.m_version
    );
}

std::ostream&
operator<< (std::ostream& os, QuicHeader& tc)
{
  tc.Print (os);
  return os;
}

} // namespace ns3

