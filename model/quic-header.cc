/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 */

#include "quic-header.h"

#include "ns3/log.h"

#include <iostream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicHeader");

NS_OBJECT_ENSURE_REGISTERED(QuicHeader);

namespace
{

/**
 * Read a variable-length integer if the bytes that are left hold all of it.
 *
 * @param i the position, moved past the integer.
 * @param left the bytes left, reduced by the bytes read.
 * @param value set to the value.
 * @return false when the integer does not fit.
 */
bool
ReadVarInt(Buffer::Iterator& i, uint32_t& left, uint64_t& value)
{
    if (left < 1)
    {
        return false;
    }
    Buffer::Iterator peek = i;
    const uint32_t length = 1U << (peek.ReadU8() >> 6);
    if (left < length)
    {
        return false;
    }
    value = QuicReadVarInt(i);
    left -= length;
    return true;
}

} // namespace

QuicHeader::QuicHeader()
    : m_form(SHORT),
      m_spinBit(false),
      m_k(PHASE_ZERO),
      m_type(NONE),
      m_pnLength(4),
      m_dcid(),
      m_scid(),
      m_packetNumber(0),
      m_version(0),
      m_payloadSize(0),
      m_shortCidLength(8),
      m_valid(true)
{
}

QuicHeader::~QuicHeader()
{
}

std::string
QuicHeader::TypeToString() const
{
    static const char* longTypeNames[6] =
        {"Version Negotiation", "Initial", "Retry", "Handshake", "0-RTT Protected", "None"};
    return IsLong() ? longTypeNames[m_type] : "Short";
}

TypeId
QuicHeader::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicHeader")
                            .SetParent<Header>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicHeader>();
    return tid;
}

TypeId
QuicHeader::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

uint8_t
QuicHeader::LongTypeBits() const
{
    // RFC 9000 Section 17.2 (version 1) and RFC 9369 Section 3.2 (version 2)
    if (m_version == QUIC_VERSION_2)
    {
        static const uint8_t v2[5] = {0, 1, 0, 3, 2};
        return v2[m_type];
    }
    static const uint8_t v1[5] = {0, 0, 3, 2, 1};
    return v1[m_type];
}

uint32_t
QuicHeader::LengthFieldSize() const
{
    return QuicVarIntLength(m_pnLength + m_payloadSize);
}

uint32_t
QuicHeader::GetSerializedSize(void) const
{
    if (IsShort())
    {
        return 1 + m_dcid.GetLength() + m_pnLength;
    }
    uint32_t size = 1 + 4 + 1 + m_dcid.GetLength() + 1 + m_scid.GetLength();
    if (IsVersionNegotiation())
    {
        return size + 4 * m_versions.size();
    }
    if (IsRetry())
    {
        return size + m_token.size();
    }
    if (IsInitial())
    {
        size += QuicVarIntLength(m_token.size()) + m_token.size();
    }
    return size + LengthFieldSize() + m_pnLength;
}

void
QuicHeader::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this);

    Buffer::Iterator i = start;

    if (IsShort())
    {
        // RFC 9000 Section 17.3.1: 0 | Fixed Bit | Spin Bit | Reserved (00) | Key Phase | Packet
        // Number Length (2)
        i.WriteU8((m_fixedBit ? 0x40 : 0) | (m_spinBit << 5) | (m_k << 2) | (m_pnLength - 1));
        m_dcid.Serialize(i);
    }
    else
    {
        // RFC 9000 Section 17.2. The unused bits of a Version Negotiation packet and of a Retry
        // packet are zero, with the Fixed Bit set.
        uint8_t first = 0xC0;
        if (IsVersionNegotiation())
        {
            first = 0xC0;
        }
        else if (IsRetry())
        {
            first = 0xC0 | (LongTypeBits() << 4);
        }
        else
        {
            first = 0xC0 | (LongTypeBits() << 4) | (m_pnLength - 1);
            if (!m_fixedBit)
            {
                first &= ~0x40;
            }
        }
        i.WriteU8(first);
        i.WriteHtonU32(IsVersionNegotiation() ? 0 : m_version);
        i.WriteU8(m_dcid.GetLength());
        m_dcid.Serialize(i);
        i.WriteU8(m_scid.GetLength());
        m_scid.Serialize(i);
        if (IsVersionNegotiation())
        {
            for (uint32_t version : m_versions)
            {
                i.WriteHtonU32(version);
            }
            return;
        }
        if (IsRetry())
        {
            if (!m_token.empty())
            {
                i.Write(m_token.data(), m_token.size());
            }
            return;
        }
        if (IsInitial())
        {
            QuicWriteVarInt(i, m_token.size());
            if (!m_token.empty())
            {
                i.Write(m_token.data(), m_token.size());
            }
        }
        QuicWriteVarInt(i, m_pnLength + m_payloadSize);
    }
    // the packet number, truncated to the bytes chosen
    const uint64_t number = m_packetNumber.GetValue();
    for (uint8_t k = 0; k < m_pnLength; ++k)
    {
        i.WriteU8(static_cast<uint8_t>(number >> (8 * (m_pnLength - 1 - k))));
    }
}

uint32_t
QuicHeader::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this);

    Buffer::Iterator i = start;
    const uint32_t total = start.GetRemainingSize();
    uint32_t left = total;
    m_valid = true;
    m_dcid = QuicConnectionId();
    m_scid = QuicConnectionId();
    m_token.clear();
    m_versions.clear();
    m_payloadSize = 0;
    m_packetNumber = QuicPacketNumber(0);

    auto fail = [&]() {
        m_valid = false;
        return total;
    };
    auto readPacketNumber = [&]() {
        uint64_t number = 0;
        for (uint8_t k = 0; k < m_pnLength; ++k)
        {
            number = (number << 8) | i.ReadU8();
        }
        left -= m_pnLength;
        m_packetNumber = QuicPacketNumber(number);
    };

    if (left < 1)
    {
        return fail();
    }
    const uint8_t first = i.ReadU8();
    --left;
    m_form = (first & 0x80) ? LONG : SHORT;

    if (IsShort())
    {
        m_type = NONE;
        m_spinBit = (first & 0x20) != 0;
        m_k = (first & 0x04) != 0;
        m_pnLength = (first & 0x03) + 1;
        m_version = 0;
        // a Fixed Bit of 0 is for the receiver to judge: it is valid when it announced
        // grease_quic_bit (RFC 9287)
        m_fixedBit = (first & 0x40) != 0;
        if (first & 0x18)
        {
            m_valid = false;
        }
        if (left < m_shortCidLength + m_pnLength)
        {
            return fail();
        }
        m_dcid = QuicConnectionId::Deserialize(i, m_shortCidLength);
        left -= m_shortCidLength;
        readPacketNumber();
        m_payloadSize = left;
        return total - left;
    }

    m_spinBit = false;
    m_k = false;
    if (left < 5)
    {
        return fail();
    }
    m_version = i.ReadNtohU32();
    left -= 4;
    const bool negotiation = m_version == 0;

    // the connection ids of a version this module speaks have at most 20 bytes
    uint8_t cidLength = i.ReadU8();
    --left;
    if (cidLength > QuicConnectionId::MAX_LENGTH || left < cidLength + 1U)
    {
        return fail();
    }
    m_dcid = QuicConnectionId::Deserialize(i, cidLength);
    left -= cidLength;
    cidLength = i.ReadU8();
    --left;
    if (cidLength > QuicConnectionId::MAX_LENGTH || left < cidLength)
    {
        return fail();
    }
    m_scid = QuicConnectionId::Deserialize(i, cidLength);
    left -= cidLength;

    if (negotiation)
    {
        m_type = VERSION_NEGOTIATION;
        m_pnLength = 4;
        if (left % 4 != 0)
        {
            m_valid = false;
        }
        while (left >= 4)
        {
            m_versions.push_back(i.ReadNtohU32());
            left -= 4;
        }
        // RFC 8999 Section 6: the bits after the form bit are not defined for this packet
        return total - left;
    }

    m_fixedBit = (first & 0x40) != 0;
    const uint8_t typeBits = (first >> 4) & 0x03;
    static const uint8_t v1[4] = {INITIAL, ZRTT_PROTECTED, HANDSHAKE, RETRY};
    static const uint8_t v2[4] = {RETRY, INITIAL, ZRTT_PROTECTED, HANDSHAKE};
    m_type = (m_version == QUIC_VERSION_2) ? v2[typeBits] : v1[typeBits];
    if (!m_fixedBit && (m_type == INITIAL || m_type == RETRY))
    {
        // no endpoint can have negotiated grease_quic_bit before these
        m_valid = false;
    }

    if (m_type == RETRY)
    {
        m_pnLength = 4;
        if (left < QUIC_AEAD_TAG_SIZE)
        {
            return fail();
        }
        m_token.resize(left - QUIC_AEAD_TAG_SIZE);
        if (!m_token.empty())
        {
            i.Read(m_token.data(), m_token.size());
        }
        left = QUIC_AEAD_TAG_SIZE;
        m_payloadSize = left;
        return total - left;
    }

    if (first & 0x0C)
    {
        m_valid = false;
    }
    m_pnLength = (first & 0x03) + 1;
    if (m_type == INITIAL)
    {
        uint64_t tokenLength = 0;
        if (!ReadVarInt(i, left, tokenLength) || tokenLength > left)
        {
            return fail();
        }
        m_token.resize(tokenLength);
        if (!m_token.empty())
        {
            i.Read(m_token.data(), m_token.size());
        }
        left -= tokenLength;
    }
    uint64_t length = 0;
    if (!ReadVarInt(i, left, length) || length < m_pnLength)
    {
        return fail();
    }
    if (length > left)
    {
        m_valid = false;
        if (left < m_pnLength)
        {
            return fail();
        }
    }
    readPacketNumber();
    m_payloadSize = static_cast<uint32_t>(length - m_pnLength);
    return total - left;
}

void
QuicHeader::Print(std::ostream& os) const
{
    os << "|" << (IsLong() ? "L" : "S") << "|" << TypeToString() << "|";
    if (IsLong())
    {
        os << "Version 0x" << std::hex << m_version << std::dec << "|";
    }
    else
    {
        os << "Spin " << m_spinBit << "|Key phase " << m_k << "|";
    }
    os << "DCID " << m_dcid << "|";
    if (IsLong())
    {
        os << "SCID " << m_scid << "|";
    }
    if (HasPacketNumber())
    {
        os << "PN " << m_packetNumber << " (" << +m_pnLength << " bytes)|";
    }
    os << "\n";
}

std::ostream&
operator<<(std::ostream& os, QuicHeader& tc)
{
    tc.Print(os);
    return os;
}

QuicHeader
QuicHeader::CreateInitial(const QuicConnectionId& dcid,
                          const QuicConnectionId& scid,
                          uint32_t version,
                          QuicPacketNumber packetNumber,
                          const std::vector<uint8_t>& token)
{
    QuicHeader head;
    head.m_form = LONG;
    head.m_type = INITIAL;
    head.m_dcid = dcid;
    head.m_scid = scid;
    head.m_version = version;
    head.m_packetNumber = packetNumber;
    head.m_token = token;
    return head;
}

QuicHeader
QuicHeader::CreateRetry(const QuicConnectionId& dcid,
                        const QuicConnectionId& scid,
                        uint32_t version,
                        const std::vector<uint8_t>& token)
{
    QuicHeader head;
    head.m_form = LONG;
    head.m_type = RETRY;
    head.m_dcid = dcid;
    head.m_scid = scid;
    head.m_version = version;
    head.m_token = token;
    return head;
}

QuicHeader
QuicHeader::CreateHandshake(const QuicConnectionId& dcid,
                            const QuicConnectionId& scid,
                            uint32_t version,
                            QuicPacketNumber packetNumber)
{
    QuicHeader head;
    head.m_form = LONG;
    head.m_type = HANDSHAKE;
    head.m_dcid = dcid;
    head.m_scid = scid;
    head.m_version = version;
    head.m_packetNumber = packetNumber;
    return head;
}

QuicHeader
QuicHeader::Create0RTT(const QuicConnectionId& dcid,
                       const QuicConnectionId& scid,
                       uint32_t version,
                       QuicPacketNumber packetNumber)
{
    QuicHeader head;
    head.m_form = LONG;
    head.m_type = ZRTT_PROTECTED;
    head.m_dcid = dcid;
    head.m_scid = scid;
    head.m_version = version;
    head.m_packetNumber = packetNumber;
    return head;
}

QuicHeader
QuicHeader::CreateVersionNegotiation(const QuicConnectionId& dcid,
                                     const QuicConnectionId& scid,
                                     const std::vector<uint32_t>& supportedVersions)
{
    QuicHeader head;
    head.m_form = LONG;
    head.m_type = VERSION_NEGOTIATION;
    head.m_dcid = dcid;
    head.m_scid = scid;
    head.m_version = 0;
    head.m_versions = supportedVersions;
    return head;
}

QuicHeader
QuicHeader::CreateShort(const QuicConnectionId& dcid,
                        QuicPacketNumber packetNumber,
                        bool keyPhaseBit,
                        bool spinBit,
                        int64_t largestAcked)
{
    QuicHeader head;
    head.m_form = SHORT;
    head.m_dcid = dcid;
    head.m_k = keyPhaseBit;
    head.m_spinBit = spinBit;
    head.m_packetNumber = packetNumber;
    head.m_pnLength = QuicPacketNumberLength(packetNumber.GetValue(), largestAcked);
    head.m_shortCidLength = dcid.GetLength();
    return head;
}

QuicConnectionId
QuicHeader::GetDestinationConnectionId() const
{
    return m_dcid;
}

QuicConnectionId
QuicHeader::GetSourceConnectionId() const
{
    return m_scid;
}

void
QuicHeader::SetConnectionIds(const QuicConnectionId& dcid, const QuicConnectionId& scid)
{
    m_dcid = dcid;
    m_scid = IsLong() ? scid : QuicConnectionId();
}

QuicPacketNumber
QuicHeader::GetPacketNumber() const
{
    return m_packetNumber;
}

uint8_t
QuicHeader::GetPacketNumberLength() const
{
    return m_pnLength;
}

void
QuicHeader::SetPacketNumber(QuicPacketNumber packetNumber)
{
    m_packetNumber = packetNumber;
}

void
QuicHeader::SetPacketNumberLength(uint8_t length)
{
    NS_ASSERT_MSG(length >= 1 && length <= 4, "a packet number has 1 to 4 bytes, got " << +length);
    m_pnLength = length;
}

void
QuicHeader::ReconstructPacketNumber(int64_t largestReceived)
{
    m_packetNumber = QuicPacketNumber(
        QuicDecodePacketNumber(largestReceived, m_packetNumber.GetValue(), m_pnLength));
}

void
QuicHeader::SetPayloadSize(uint32_t size)
{
    m_payloadSize = size;
}

uint32_t
QuicHeader::GetPayloadSize() const
{
    return m_payloadSize;
}

uint32_t
QuicHeader::GetVersion() const
{
    NS_ASSERT(HasVersion());
    return m_version;
}

void
QuicHeader::SetVersion(uint32_t version)
{
    NS_ASSERT(HasVersion());
    m_version = version;
}

const std::vector<uint8_t>&
QuicHeader::GetToken() const
{
    return m_token;
}

const std::vector<uint32_t>&
QuicHeader::GetSupportedVersions() const
{
    return m_versions;
}

bool
QuicHeader::GetKeyPhaseBit() const
{
    NS_ASSERT(IsShort());
    return m_k;
}

void
QuicHeader::SetKeyPhaseBit(bool keyPhaseBit)
{
    NS_ASSERT(IsShort());
    m_k = keyPhaseBit;
}

bool
QuicHeader::GetSpinBit() const
{
    NS_ASSERT(IsShort());
    return m_spinBit;
}

void
QuicHeader::SetSpinBit(bool spinBit)
{
    NS_ASSERT(IsShort());
    m_spinBit = spinBit;
}

void
QuicHeader::SetShortHeaderConnectionIdLength(uint8_t length)
{
    NS_ASSERT(length <= QuicConnectionId::MAX_LENGTH);
    m_shortCidLength = length;
}

bool
QuicHeader::IsValid() const
{
    return m_valid;
}

uint8_t
QuicHeader::GetFormat() const
{
    return m_form;
}

bool
QuicHeader::IsShort() const
{
    return m_form == SHORT;
}

bool
QuicHeader::IsVersionNegotiation() const
{
    return IsLong() && m_type == VERSION_NEGOTIATION;
}

bool
QuicHeader::IsInitial() const
{
    return IsLong() && m_type == INITIAL;
}

bool
QuicHeader::IsRetry() const
{
    return IsLong() && m_type == RETRY;
}

bool
QuicHeader::IsHandshake() const
{
    return IsLong() && m_type == HANDSHAKE;
}

bool
QuicHeader::IsORTT() const
{
    return IsLong() && m_type == ZRTT_PROTECTED;
}

QuicPacketType
QuicHeader::GetPacketType() const
{
    if (IsShort())
    {
        return QuicPacketType::ONE_RTT;
    }
    switch (m_type)
    {
    case INITIAL:
        return QuicPacketType::INITIAL;
    case ZRTT_PROTECTED:
        return QuicPacketType::ZERO_RTT;
    case HANDSHAKE:
        return QuicPacketType::HANDSHAKE;
    default:
        NS_ABORT_MSG("Version Negotiation and Retry packets carry no frames");
    }
}

bool
QuicHeader::HasPacketNumber() const
{
    return !IsVersionNegotiation() && !IsRetry();
}

bool
QuicHeader::HasAeadTag() const
{
    return !IsVersionNegotiation();
}

bool
QuicHeader::HasVersion() const
{
    return IsLong();
}

bool
operator==(const QuicHeader& lhs, const QuicHeader& rhs)
{
    return lhs.m_form == rhs.m_form && lhs.m_spinBit == rhs.m_spinBit && lhs.m_k == rhs.m_k &&
           lhs.m_type == rhs.m_type && lhs.m_pnLength == rhs.m_pnLength &&
           lhs.m_dcid == rhs.m_dcid && lhs.m_scid == rhs.m_scid &&
           lhs.m_packetNumber == rhs.m_packetNumber && lhs.m_version == rhs.m_version &&
           lhs.m_payloadSize == rhs.m_payloadSize && lhs.m_token == rhs.m_token &&
           lhs.m_versions == rhs.m_versions;
}

} // namespace ns3
