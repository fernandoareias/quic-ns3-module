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

#include "quic-subheader.h"

#include "quic-wire.h"

#include "ns3/address-utils.h"
#include "ns3/buffer.h"
#include "ns3/log.h"

#include <algorithm>
#include <iostream>
#include <stdint.h>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicSubheader");

NS_OBJECT_ENSURE_REGISTERED(QuicSubheader);

QuicSubheader::QuicSubheader()
    : m_frameType(PADDING),
      m_streamId(0),
      m_errorCode(0),
      m_offset(0),
      m_reasonPhraseLength(0),
      m_maxData(0),
      m_maxStreamData(0),
      m_maxStreamId(0),
      m_sequence(0),
      m_connectionId(0),
      m_largestAcknowledged(0),
      m_ackDelay(0),
      m_ackBlockCount(0),
      m_firstAckBlock(0),
      m_data(0),
      m_length(0)
{
    m_reasonPhrase = std::vector<uint8_t>();
    m_additionalAckBlocks = std::vector<uint32_t>();
    m_gaps = std::vector<uint32_t>();
}

QuicSubheader::~QuicSubheader()
{
}

TypeId
QuicSubheader::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicSubHeader")
                            .SetParent<Header>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicSubheader>();
    return tid;
}

TypeId
QuicSubheader::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

std::string
QuicSubheader::FrameTypeToString() const
{
    // RFC 9000 §19 — frame type names indexed by wire value (0x00–0x1e)
    static const char* frameTypeNames[31] = {
        "PADDING",              // 0x00
        "PING",                 // 0x01
        "ACK",                  // 0x02
        "ACK_ECN",              // 0x03
        "RESET_STREAM",         // 0x04
        "STOP_SENDING",         // 0x05
        "CRYPTO",               // 0x06
        "NEW_TOKEN",            // 0x07
        "STREAM",               // 0x08
        "STREAM_FIN",           // 0x09
        "STREAM_LEN",           // 0x0a
        "STREAM_LEN_FIN",       // 0x0b
        "STREAM_OFF",           // 0x0c
        "STREAM_OFF_FIN",       // 0x0d
        "STREAM_OFF_LEN",       // 0x0e
        "STREAM_OFF_LEN_FIN",   // 0x0f
        "MAX_DATA",             // 0x10
        "MAX_STREAM_DATA",      // 0x11
        "MAX_STREAMS_BIDI",     // 0x12
        "MAX_STREAMS_UNI",      // 0x13
        "DATA_BLOCKED",         // 0x14
        "STREAM_DATA_BLOCKED",  // 0x15
        "STREAMS_BLOCKED_BIDI", // 0x16
        "STREAMS_BLOCKED_UNI",  // 0x17
        "NEW_CONNECTION_ID",    // 0x18
        "RETIRE_CONNECTION_ID", // 0x19
        "PATH_CHALLENGE",       // 0x1a
        "PATH_RESPONSE",        // 0x1b
        "CONNECTION_CLOSE",     // 0x1c
        "CONNECTION_CLOSE_APP", // 0x1d
        "HANDSHAKE_DONE"        // 0x1e
    };
    std::string typeDescription = "";

    if (m_frameType <= HANDSHAKE_DONE)
    {
        typeDescription.append(frameTypeNames[m_frameType]);
    }
    else if (m_frameType == IMMEDIATE_ACK)
    {
        typeDescription = "IMMEDIATE_ACK";
    }
    else if (m_frameType == ACK_FREQUENCY)
    {
        typeDescription = "ACK_FREQUENCY";
    }
    else
    {
        typeDescription = "UNKNOWN_FRAME_TYPE";
    }

    return typeDescription;
}

std::string
QuicSubheader::TransportErrorCodeToString() const
{
    // RFC 9000 §20 — transport error code names indexed by wire value
    static const char* transportErrorCodeNames[17] = {
        "NO_ERROR",                  // 0x00
        "INTERNAL_ERROR",            // 0x01
        "CONNECTION_REFUSED",        // 0x02
        "FLOW_CONTROL_ERROR",        // 0x03
        "STREAM_LIMIT_ERROR",        // 0x04
        "STREAM_STATE_ERROR",        // 0x05
        "FINAL_SIZE_ERROR",          // 0x06
        "FRAME_ENCODING_ERROR",      // 0x07
        "TRANSPORT_PARAMETER_ERROR", // 0x08
        "CONNECTION_ID_LIMIT_ERROR", // 0x09
        "PROTOCOL_VIOLATION",        // 0x0a
        "INVALID_TOKEN",             // 0x0b
        "APPLICATION_ERROR",         // 0x0c
        "CRYPTO_BUFFER_EXCEEDED",    // 0x0d
        "KEY_UPDATE_ERROR",          // 0x0e
        "AEAD_LIMIT_REACHED",        // 0x0f
        "NO_VIABLE_PATH"             // 0x10
    };
    std::string typeDescription = "";

    if (m_errorCode <= 0x10)
    {
        typeDescription.append(transportErrorCodeNames[m_errorCode]);
    }
    else if (m_errorCode >= 0x100)
    {
        typeDescription = "CRYPTO_ERROR(TLS_ALERT=" + std::to_string(m_errorCode - 0x100) + ")";
    }
    else
    {
        typeDescription = "UNKNOWN_ERROR_CODE";
    }

    return typeDescription;
}

std::vector<uint64_t>
QuicSubheader::AckWireRanges() const
{
    // In memory the ranges are absolute packet numbers: range 0 is (m_gaps[0], largest], range k is
    // (m_gaps[k], m_additionalAckBlocks[k - 1]] and the last one ends at m_firstAckBlock (the ACK
    // floor). On the wire (RFC 9000 s19.3.1) they are counts: the length of the first range, then
    // for each older range the number of packets missing between it and the newer one (minus one)
    // and its own length (minus one).
    auto lowest = [this](uint64_t k) -> int64_t {
        return (k < m_ackBlockCount) ? (int64_t)m_gaps[k] + 1 : (int64_t)m_firstAckBlock;
    };
    std::vector<uint64_t> wire;
    int64_t lo = lowest(0);
    wire.push_back((uint64_t)std::max<int64_t>((int64_t)m_largestAcknowledged - lo, 0));
    for (uint64_t k = 1; k <= m_ackBlockCount; ++k)
    {
        int64_t hi = (int64_t)m_additionalAckBlocks[k - 1];
        int64_t olderLo = lowest(k);
        wire.push_back((uint64_t)std::max<int64_t>(lo - hi - 2, 0));
        wire.push_back((uint64_t)std::max<int64_t>(hi - olderLo, 0));
        lo = olderLo;
    }
    return wire;
}

void
QuicSubheader::ReadAckRanges(Buffer::Iterator& i)
{
    // inverse of AckWireRanges ()
    m_ackBlockCount = ReadVarInt64(i);
    m_gaps.clear();
    m_additionalAckBlocks.clear();
    int64_t lo = (int64_t)m_largestAcknowledged -
                 (int64_t)ReadVarInt64(i); // lowest packet of the first range
    for (uint64_t k = 1; k <= m_ackBlockCount; ++k)
    {
        m_gaps.push_back((uint32_t)std::max<int64_t>(lo - 1, 0));
        int64_t hi = lo - (int64_t)ReadVarInt64(i) - 2;
        lo = hi - (int64_t)ReadVarInt64(i);
        m_additionalAckBlocks.push_back((uint32_t)std::max<int64_t>(hi, 0));
    }
    m_firstAckBlock = (uint32_t)std::max<int64_t>(lo, 0);
}

uint32_t
QuicSubheader::GetSerializedSize(void) const
{
    NS_LOG_FUNCTION(this << (uint64_t)m_frameType);

    return CalculateSubHeaderLength();
}

uint32_t
QuicSubheader::CalculateSubHeaderLength() const
{
    NS_LOG_FUNCTION(this);
    NS_ASSERT(m_frameType <= IMMEDIATE_ACK or m_frameType == ACK_FREQUENCY);
    uint32_t len = 8;

    switch (m_frameType)
    {
    case PADDING:

        break;

    case RESET_STREAM: // 0x04 RFC 9000 §19.4

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_errorCode);
        len += GetVarInt64Size(m_offset);
        break;

    case CONNECTION_CLOSE: // 0x1c RFC 9000 §19.19: error code, frame type, reason

        len += GetVarInt64Size(m_errorCode);
        len += GetVarInt64Size(m_triggerFrameType);
        len += GetVarInt64Size(m_reasonPhraseLength);
        len += (m_reasonPhraseLength * 8);
        break;

    case CONNECTION_CLOSE_APP: // 0x1d RFC 9000 §19.19: error code, reason

        len += GetVarInt64Size(m_errorCode);
        len += GetVarInt64Size(m_reasonPhraseLength);
        len += (m_reasonPhraseLength * 8);
        break;

    case MAX_DATA: // 0x10 RFC 9000 §19.9

        len += GetVarInt64Size(m_maxData);
        break;

    case MAX_STREAM_DATA: // 0x11 RFC 9000 §19.10

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_maxStreamData);
        break;

    case MAX_STREAMS_BIDI: // 0x12 RFC 9000 §19.11
    case MAX_STREAMS_UNI:  // 0x13 RFC 9000 §19.11

        len += GetVarInt64Size(m_maxStreamId);
        break;

    case PING:           // 0x01 RFC 9000 §19.2
    case HANDSHAKE_DONE: // 0x1e RFC 9000 §19.20
    case IMMEDIATE_ACK:  // 0x1f ack-frequency draft

        break;

    case ACK_FREQUENCY: // 0xaf ack-frequency draft

        len += GetVarInt64Size(m_ackFreqSeq);
        len += GetVarInt64Size(m_ackFreqThreshold);
        len += GetVarInt64Size(m_ackFreqMaxDelayUs);
        len += GetVarInt64Size(m_ackFreqReordering);
        break;

    case DATA_BLOCKED: // 0x14 RFC 9000 §19.12

        len += GetVarInt64Size(m_offset);
        break;

    case STREAM_DATA_BLOCKED: // 0x15 RFC 9000 §19.13

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_offset);
        break;

    case STREAMS_BLOCKED_BIDI: // 0x16 RFC 9000 §19.14
    case STREAMS_BLOCKED_UNI:  // 0x17 RFC 9000 §19.14

        len += GetVarInt64Size(m_streamId);
        break;

    case NEW_CONNECTION_ID: // 0x18 RFC 9000 §19.15

        len += GetVarInt64Size(m_sequence);
        len += GetVarInt64Size(m_retirePriorTo);
        len += 8;   // connection id length (RFC 9000 s19.15)
        len += 64;  // connection id (this module issues 8-byte ids)
        len += 128; // stateless reset token
        break;

    case RETIRE_CONNECTION_ID: // 0x19 RFC 9000 §19.16

        len += GetVarInt64Size(m_sequence);
        break;

    case STOP_SENDING: // 0x05 RFC 9000 §19.5

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_errorCode);
        break;

    case ACK: // 0x02 RFC 9000 §19.3

        len += GetVarInt64Size(m_largestAcknowledged);
        len += GetVarInt64Size(m_ackDelay);
        len += GetVarInt64Size(m_ackBlockCount);
        for (uint64_t v : AckWireRanges())
        {
            len += GetVarInt64Size(v);
        }
        break;

    case ACK_ECN: // 0x03 RFC 9000 §19.3 + §19.3.2

        len += GetVarInt64Size(m_largestAcknowledged);
        len += GetVarInt64Size(m_ackDelay);
        len += GetVarInt64Size(m_ackBlockCount);
        for (uint64_t v : AckWireRanges())
        {
            len += GetVarInt64Size(v);
        }
        // ECN Counts section (RFC 9000 §19.3.2)
        len += GetVarInt64Size(m_ect0Count);
        len += GetVarInt64Size(m_ect1Count);
        len += GetVarInt64Size(m_ecnCeCount);
        break;

    case PATH_CHALLENGE: // 0x1a RFC 9000 §19.17

        len += 64; // 8 octets of opaque data, RFC 9000 §19.17
        break;

    case PATH_RESPONSE: // 0x1b RFC 9000 §19.18

        len += 64; // 8 octets of opaque data, RFC 9000 §19.18
        break;

    // STREAM variants 0x08–0x0f: base + OFF(0x04) + LEN(0x02) + FIN(0x01)
    case STREAM: // 0x08 no offset, no length

        len += GetVarInt64Size(m_streamId);
        break;

    case STREAM_FIN: // 0x09 FIN only

        len += GetVarInt64Size(m_streamId);
        break;

    case STREAM_LEN: // 0x0a LEN only

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_length);
        break;

    case STREAM_LEN_FIN: // 0x0b LEN + FIN

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_length);
        break;

    case STREAM_OFF: // 0x0c OFF only

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_offset);
        break;

    case STREAM_OFF_FIN: // 0x0d OFF + FIN

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_offset);
        break;

    case STREAM_OFF_LEN: // 0x0e OFF + LEN

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_offset);
        len += GetVarInt64Size(m_length);
        break;

    case STREAM_OFF_LEN_FIN: // 0x0f OFF + LEN + FIN

        len += GetVarInt64Size(m_streamId);
        len += GetVarInt64Size(m_offset);
        len += GetVarInt64Size(m_length);
        break;
    }

    NS_LOG_LOGIC("CalculateSubHeaderLength - len" << len << " " << len / 8);

    NS_ABORT_MSG_IF(len % 8 != 0, "len not divisible by 8 " << len);
    // NS_ABORT_MSG_IF (len > 255, "len too long " << len);

    return (len / 8);
}

void
QuicSubheader::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this << (uint64_t)m_frameType);
    NS_ASSERT(m_frameType <= IMMEDIATE_ACK or m_frameType == ACK_FREQUENCY);

    Buffer::Iterator i = start;
    i.WriteU8((uint8_t)m_frameType);

    switch (m_frameType)
    {
    case PADDING:

        break;

    case RESET_STREAM:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_errorCode);
        WriteVarInt64(i, m_offset);
        break;

    case CONNECTION_CLOSE:
    case CONNECTION_CLOSE_APP:

        WriteVarInt64(i, m_errorCode);
        if (m_frameType == CONNECTION_CLOSE)
        {
            WriteVarInt64(
                i,
                m_triggerFrameType); // RFC 9000 s19.19: only the transport close names the frame
        }
        WriteVarInt64(i, m_reasonPhraseLength);
        for (auto& elem : m_reasonPhrase)
        {
            i.WriteU8(elem);
        }
        break;

    case MAX_DATA:

        WriteVarInt64(i, m_maxData);
        break;

    case MAX_STREAM_DATA:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_maxStreamData);
        break;

    case MAX_STREAMS_BIDI:
    case MAX_STREAMS_UNI:

        WriteVarInt64(i, m_maxStreamId);
        break;

    case PING:
    case HANDSHAKE_DONE:
    case IMMEDIATE_ACK:

        break;

    case ACK_FREQUENCY:

        WriteVarInt64(i, m_ackFreqSeq);
        WriteVarInt64(i, m_ackFreqThreshold);
        WriteVarInt64(i, m_ackFreqMaxDelayUs);
        WriteVarInt64(i, m_ackFreqReordering);
        break;

    case DATA_BLOCKED:

        WriteVarInt64(i, m_offset);
        break;

    case STREAM_DATA_BLOCKED:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_offset);
        break;

    case STREAMS_BLOCKED_BIDI:
    case STREAMS_BLOCKED_UNI:

        WriteVarInt64(i, m_streamId);
        break;

    case NEW_CONNECTION_ID:

        WriteVarInt64(i, m_sequence);
        WriteVarInt64(i, m_retirePriorTo);
        i.WriteU8(8); // RFC 9000 s19.15: connection id length
        i.WriteHtonU64(m_connectionId);
        i.WriteHtonU64(m_resetTokenHi);
        i.WriteHtonU64(m_resetTokenLo);
        break;

    case RETIRE_CONNECTION_ID:

        WriteVarInt64(i, m_sequence);
        break;

    case STOP_SENDING:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_errorCode);
        break;

    case ACK:

        WriteVarInt64(i, m_largestAcknowledged);
        WriteVarInt64(i, m_ackDelay);
        WriteVarInt64(i, m_ackBlockCount);
        for (uint64_t v : AckWireRanges())
        {
            WriteVarInt64(i, v);
        }
        break;

    case ACK_ECN:

        WriteVarInt64(i, m_largestAcknowledged);
        WriteVarInt64(i, m_ackDelay);
        WriteVarInt64(i, m_ackBlockCount);
        for (uint64_t v : AckWireRanges())
        {
            WriteVarInt64(i, v);
        }
        // ECN Counts section (RFC 9000 §19.3.2)
        WriteVarInt64(i, m_ect0Count);
        WriteVarInt64(i, m_ect1Count);
        WriteVarInt64(i, m_ecnCeCount);
        break;

    case PATH_CHALLENGE:

        i.WriteHtonU64(m_data); // RFC 9000 §19.17: 8-octet opaque data
        break;

    case PATH_RESPONSE:

        i.WriteHtonU64(m_data); // RFC 9000 §19.18: 8-octet opaque data
        break;

    case STREAM:
    case STREAM_FIN:

        WriteVarInt64(i, m_streamId);
        break;

    case STREAM_LEN:
    case STREAM_LEN_FIN:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_length);
        break;

    case STREAM_OFF:
    case STREAM_OFF_FIN:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_offset);
        break;

    case STREAM_OFF_LEN:
    case STREAM_OFF_LEN_FIN:

        WriteVarInt64(i, m_streamId);
        WriteVarInt64(i, m_offset);
        WriteVarInt64(i, m_length);
        break;
    }
}

uint32_t
QuicSubheader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    m_frameType = i.ReadU8();

    NS_LOG_FUNCTION(this << (uint64_t)m_frameType);

    NS_ASSERT(m_frameType <= IMMEDIATE_ACK or m_frameType == ACK_FREQUENCY);

    switch (m_frameType)
    {
    case PADDING:

        break;

    case RESET_STREAM:

        m_streamId = ReadVarInt64(i);
        m_errorCode = (uint16_t)ReadVarInt64(i);
        m_offset = ReadVarInt64(i);
        break;

    case CONNECTION_CLOSE:
    case CONNECTION_CLOSE_APP:

        m_errorCode = (uint16_t)ReadVarInt64(i);
        if (m_frameType == CONNECTION_CLOSE)
        {
            m_triggerFrameType = ReadVarInt64(i);
        }
        m_reasonPhraseLength = ReadVarInt64(i);
        for (uint64_t j = 0; j < m_reasonPhraseLength; j++)
        {
            m_reasonPhrase.push_back(i.ReadU8());
        }
        break;

    case MAX_DATA:

        m_maxData = ReadVarInt64(i);
        break;

    case MAX_STREAM_DATA:

        m_streamId = ReadVarInt64(i);
        m_maxStreamData = ReadVarInt64(i);
        break;

    case MAX_STREAMS_BIDI:
    case MAX_STREAMS_UNI:

        m_maxStreamId = ReadVarInt64(i);
        break;

    case PING:
    case HANDSHAKE_DONE:
    case IMMEDIATE_ACK:

        break;

    case ACK_FREQUENCY:

        m_ackFreqSeq = ReadVarInt64(i);
        m_ackFreqThreshold = ReadVarInt64(i);
        m_ackFreqMaxDelayUs = ReadVarInt64(i);
        m_ackFreqReordering = ReadVarInt64(i);
        break;

    case DATA_BLOCKED:

        m_offset = ReadVarInt64(i);
        break;

    case STREAM_DATA_BLOCKED:

        m_streamId = ReadVarInt64(i);
        m_offset = ReadVarInt64(i);
        break;

    case STREAMS_BLOCKED_BIDI:
    case STREAMS_BLOCKED_UNI:

        m_streamId = ReadVarInt64(i);
        break;

    case NEW_CONNECTION_ID:

        m_sequence = ReadVarInt64(i);
        m_retirePriorTo = ReadVarInt64(i);
        {
            // RFC 9000 s19.15: the id comes with its length; this module issues 8-byte ids and
            // keeps the last 8 bytes of a longer one
            uint8_t cidLength = i.ReadU8();
            m_connectionId = 0;
            for (uint8_t k = 0; k < cidLength; ++k)
            {
                m_connectionId = (m_connectionId << 8) | i.ReadU8();
            }
        }
        m_resetTokenHi = i.ReadNtohU64();
        m_resetTokenLo = i.ReadNtohU64();
        break;

    case RETIRE_CONNECTION_ID:

        m_sequence = ReadVarInt64(i);
        break;

    case STOP_SENDING:

        m_streamId = ReadVarInt64(i);
        m_errorCode = (uint16_t)ReadVarInt64(i);
        break;

    case ACK:

        m_largestAcknowledged = ReadVarInt64(i);
        m_ackDelay = ReadVarInt64(i);
        ReadAckRanges(i);
        break;

    case ACK_ECN:

        m_largestAcknowledged = ReadVarInt64(i);
        m_ackDelay = ReadVarInt64(i);
        ReadAckRanges(i);
        // ECN Counts section (RFC 9000 §19.3.2)
        m_ect0Count = ReadVarInt64(i);
        m_ect1Count = ReadVarInt64(i);
        m_ecnCeCount = ReadVarInt64(i);
        break;

    case PATH_CHALLENGE:

        m_data = i.ReadNtohU64(); // RFC 9000 §19.17: 8-octet opaque data
        break;

    case PATH_RESPONSE:

        m_data = i.ReadNtohU64(); // RFC 9000 §19.18: 8-octet opaque data
        break;

    case STREAM:
    case STREAM_FIN:

        m_streamId = ReadVarInt64(i);
        break;

    case STREAM_LEN:
    case STREAM_LEN_FIN:

        m_streamId = ReadVarInt64(i);
        m_length = ReadVarInt64(i);
        break;

    case STREAM_OFF:
    case STREAM_OFF_FIN:

        m_streamId = ReadVarInt64(i);
        m_offset = ReadVarInt64(i);
        break;

    case STREAM_OFF_LEN:
    case STREAM_OFF_LEN_FIN:

        m_streamId = ReadVarInt64(i);
        m_offset = ReadVarInt64(i);
        m_length = ReadVarInt64(i);
        break;
    }

    NS_LOG_INFO("Deserialized a subheader of size " << GetSerializedSize());
    return GetSerializedSize();
}

void
QuicSubheader::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this << (uint64_t)m_frameType);
    NS_ASSERT(m_frameType <= IMMEDIATE_ACK or m_frameType == ACK_FREQUENCY);

    os << "|" << FrameTypeToString() << "|\n";
    switch (m_frameType)
    {
    case PADDING:

        break;

    case RESET_STREAM:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Application Error Code " << m_errorCode << "|\n";
        os << "|Final Size " << m_offset << "|\n";
        break;

    case CONNECTION_CLOSE:
    case CONNECTION_CLOSE_APP:

        os << "|Error Code " << TransportErrorCodeToString() << "|\n";
        os << "|Reason Phrase Length " << m_reasonPhraseLength << "|\n";
        os << "|Reason Phrase ";
        for (auto& elem : m_reasonPhrase)
        {
            os << elem;
        }
        os << "|\n";
        break;

    case MAX_DATA:

        os << "|Maximum Data " << m_maxData << "|\n";
        break;

    case MAX_STREAM_DATA:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Maximum Stream Data " << m_maxStreamData << "|\n";
        break;

    case MAX_STREAMS_BIDI:
    case MAX_STREAMS_UNI:

        os << "|Maximum Streams " << m_maxStreamId << "|\n";
        break;

    case PING:
    case HANDSHAKE_DONE:
    case IMMEDIATE_ACK:

        break;

    case ACK_FREQUENCY:

        os << "|Ack Frequency seq " << m_ackFreqSeq << " threshold " << m_ackFreqThreshold
           << " max delay " << m_ackFreqMaxDelayUs << "us reordering " << m_ackFreqReordering
           << "|\n";
        break;

    case DATA_BLOCKED:

        os << "|Offset " << m_offset << "|\n";
        break;

    case STREAM_DATA_BLOCKED:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Offset " << m_offset << "|\n";
        break;

    case STREAMS_BLOCKED_BIDI:
    case STREAMS_BLOCKED_UNI:

        os << "|Stream Id " << m_streamId << "|\n";
        break;

    case NEW_CONNECTION_ID:

        os << "|Sequence " << m_sequence << "|\n";
        os << "|Retire Prior To " << m_retirePriorTo << "|\n";
        os << "|Connection Id " << m_connectionId << "|\n";
        os << "|Stateless Reset Token " << m_resetTokenHi << m_resetTokenLo << "|\n";
        break;

    case RETIRE_CONNECTION_ID:

        os << "|Sequence " << m_sequence << "|\n";
        break;

    case STOP_SENDING:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Application Error Code " << m_errorCode << "|\n";
        break;

    case ACK:
    case ACK_ECN:

        os << "|Largest Acknowledged " << m_largestAcknowledged << "|\n";
        os << "|Ack Delay " << m_ackDelay << "|\n";
        os << "|Ack Block Count " << m_ackBlockCount << "|\n";
        os << "|First Ack Block " << m_firstAckBlock << "|\n";
        for (uint64_t j = 0; j < m_ackBlockCount; j++)
        {
            os << "|Gap " << m_gaps[j] << "|\n";
            os << "|Additional Ack Block " << m_additionalAckBlocks[j] << "|\n";
        }
        break;

    case PATH_CHALLENGE:

        os << "|Data " << (uint64_t)m_data << "|\n";
        break;

    case PATH_RESPONSE:

        os << "|Data " << (uint64_t)m_data << "|\n";
        break;

    case STREAM:
    case STREAM_FIN:

        os << "|Stream Id " << m_streamId << "|\n";
        break;

    case STREAM_LEN:
    case STREAM_LEN_FIN:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Length " << m_length << "|\n";
        break;

    case STREAM_OFF:
    case STREAM_OFF_FIN:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Offset " << m_offset << "|\n";
        break;

    case STREAM_OFF_LEN:
    case STREAM_OFF_LEN_FIN:

        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Offset " << m_offset << "|\n";
        os << "|Length " << m_length << "|\n";
        break;
    }
}

bool
operator==(const QuicSubheader& lhs, const QuicSubheader& rhs)
{
    return (lhs.m_frameType == rhs.m_frameType);
}

std::ostream&
operator<<(std::ostream& os, QuicSubheader& tc)
{
    tc.Print(os);
    return os;
}

void
QuicSubheader::WriteVarInt64(Buffer::Iterator& i, uint64_t varInt64) const
{
    QuicWriteVarInt(i, varInt64);
}

uint64_t
QuicSubheader::ReadVarInt64(Buffer::Iterator& i)
{
    return QuicReadVarInt(i);
}

uint32_t
QuicSubheader::GetVarInt64Size(uint64_t varInt64)
{
    return 8 * QuicVarIntLength(varInt64);
}

QuicSubheader
QuicSubheader::CreatePadding(void)
{
    NS_LOG_INFO("Created Padding Header");

    QuicSubheader sub;
    sub.SetFrameType(PADDING);

    return sub;
}

QuicSubheader
QuicSubheader::CreateRstStream(uint64_t streamId,
                               uint16_t applicationErrorCode,
                               uint64_t finalOffset)
{
    NS_LOG_INFO("Created RstStream Header");

    QuicSubheader sub;
    sub.SetFrameType(RESET_STREAM);
    sub.SetStreamId(streamId);
    sub.SetErrorCode(applicationErrorCode);
    sub.SetOffset(finalOffset);

    return sub;
}

QuicSubheader
QuicSubheader::CreateConnectionClose(uint16_t errorCode, const char* reasonPhrase)
{
    NS_LOG_INFO("Created ConnectionClose Header");

    QuicSubheader sub;
    sub.SetFrameType(CONNECTION_CLOSE);
    sub.SetErrorCode(errorCode);

    std::vector<uint8_t> rpvec;
    for (int i = 0; reasonPhrase[i] != '\0'; i++)
    {
        rpvec.push_back((uint8_t)reasonPhrase[i]);
    }

    sub.SetReasonPhraseLength(rpvec.size());
    sub.SetReasonPhrase(rpvec);

    return sub;
}

QuicSubheader
QuicSubheader::CreateApplicationClose(uint16_t errorCode, const char* reasonPhrase)
{
    NS_LOG_INFO("Created ApplicationClose Header");

    QuicSubheader sub;
    sub.SetFrameType(CONNECTION_CLOSE_APP);
    sub.SetErrorCode(errorCode);

    std::vector<uint8_t> rpvec;
    for (int i = 0; reasonPhrase[i] != '\0'; i++)
    {
        rpvec.push_back((uint8_t)reasonPhrase[i]);
    }

    sub.SetReasonPhraseLength(rpvec.size());
    sub.SetReasonPhrase(rpvec);

    return sub;
}

QuicSubheader
QuicSubheader::CreateMaxData(uint64_t maxData)
{
    NS_LOG_INFO("Created MaxData Header");

    QuicSubheader sub;
    sub.SetFrameType(MAX_DATA);
    sub.SetMaxData(maxData);
    sub.SetLength(0);

    return sub;
}

QuicSubheader
QuicSubheader::CreateMaxStreamData(uint64_t streamId, uint64_t maxStreamData)
{
    NS_LOG_INFO("Created MaxStreamData Header");

    QuicSubheader sub;
    sub.SetFrameType(MAX_STREAM_DATA);
    sub.SetStreamId(streamId);
    sub.SetMaxStreamData(maxStreamData);

    return sub;
}

QuicSubheader
QuicSubheader::CreateMaxStreamId(uint64_t maxStreamId)
{
    NS_LOG_INFO("Created MaxStreamId Header");

    QuicSubheader sub;
    sub.SetFrameType(MAX_STREAMS_BIDI);
    sub.SetMaxStreamId(maxStreamId);

    return sub;
}

QuicSubheader
QuicSubheader::CreatePing(void)
{
    NS_LOG_INFO("Created Ping Header");

    QuicSubheader sub;
    sub.SetFrameType(PING);

    return sub;
}

QuicSubheader
QuicSubheader::CreateBlocked(uint64_t offset)
{
    NS_LOG_INFO("Created Blocked Header");

    QuicSubheader sub;
    sub.SetFrameType(DATA_BLOCKED);
    sub.SetOffset(offset);

    return sub;
}

QuicSubheader
QuicSubheader::CreateStreamBlocked(uint64_t streamId, uint64_t offset)
{
    NS_LOG_INFO("Created StreamBlocked Header");

    QuicSubheader sub;
    sub.SetFrameType(STREAM_DATA_BLOCKED);
    sub.SetStreamId(streamId);
    sub.SetOffset(offset);

    return sub;
}

QuicSubheader
QuicSubheader::CreateStreamIdBlocked(uint64_t streamId)
{
    NS_LOG_INFO("Created StreamIdBlocked Header");

    QuicSubheader sub;
    sub.SetFrameType(STREAMS_BLOCKED_BIDI);
    sub.SetStreamId(streamId);

    return sub;
}

QuicSubheader
QuicSubheader::CreateNewConnectionId(uint64_t sequence,
                                     uint64_t connectionId) // uint128_t statelessResetToken);
{
    NS_LOG_INFO("Created NewConnectionId Header");

    QuicSubheader sub;
    sub.SetFrameType(NEW_CONNECTION_ID);
    sub.SetSequence(sequence);
    sub.SetConnectionId(connectionId);

    return sub;
}

QuicSubheader
QuicSubheader::CreateNewConnectionId(uint64_t sequence,
                                     uint64_t retirePriorTo,
                                     uint64_t connectionId,
                                     uint64_t tokenHi,
                                     uint64_t tokenLo)
{
    QuicSubheader sub;
    sub.SetFrameType(NEW_CONNECTION_ID);
    sub.SetSequence(sequence);
    sub.m_retirePriorTo = retirePriorTo;
    sub.SetConnectionId(connectionId);
    sub.m_resetTokenHi = tokenHi;
    sub.m_resetTokenLo = tokenLo;
    return sub;
}

QuicSubheader
QuicSubheader::CreateRetireConnectionId(uint64_t sequence)
{
    QuicSubheader sub;
    sub.SetFrameType(RETIRE_CONNECTION_ID);
    sub.SetSequence(sequence);
    return sub;
}

QuicSubheader
QuicSubheader::CreateStopSending(uint64_t streamId, uint16_t applicationErrorCode)
{
    NS_LOG_INFO("Created StopSending Header");

    QuicSubheader sub;
    sub.SetFrameType(STOP_SENDING);
    sub.SetStreamId(streamId);
    sub.SetErrorCode(applicationErrorCode);

    return sub;
}

QuicSubheader
QuicSubheader::CreateAck(uint32_t largestAcknowledged,
                         uint64_t ackDelay,
                         uint32_t firstAckBlock,
                         std::vector<uint32_t>& gaps,
                         std::vector<uint32_t>& additionalAckBlocks)
{
    NS_LOG_INFO("Created Ack Header");

    QuicSubheader sub;
    sub.SetFrameType(ACK);
    sub.SetLargestAcknowledged(largestAcknowledged);
    sub.SetAckDelay(ackDelay);
    sub.SetAckBlockCount(gaps.size());
    sub.SetFirstAckBlock(firstAckBlock);
    sub.SetGaps(gaps);
    sub.SetAdditionalAckBlocks(additionalAckBlocks);

    return sub;
}

QuicSubheader
QuicSubheader::CreatePathChallenge(uint64_t data)
{
    NS_LOG_INFO("Created PathChallenge Header");

    QuicSubheader sub;
    sub.SetFrameType(PATH_CHALLENGE);
    sub.SetData(data);

    return sub;
}

QuicSubheader
QuicSubheader::CreatePathResponse(uint64_t data)
{
    NS_LOG_INFO("Created PathResponse Header");

    QuicSubheader sub;
    sub.SetFrameType(PATH_RESPONSE);
    sub.SetData(data);

    return sub;
}

QuicSubheader
QuicSubheader::CreateAckFrequency(uint64_t sequence,
                                  uint64_t ackElicitingThreshold,
                                  uint64_t maxAckDelayUs,
                                  uint64_t reorderingThreshold)
{
    QuicSubheader sub;
    sub.SetFrameType(ACK_FREQUENCY);
    sub.m_ackFreqSeq = sequence;
    sub.m_ackFreqThreshold = ackElicitingThreshold;
    sub.m_ackFreqMaxDelayUs = maxAckDelayUs;
    sub.m_ackFreqReordering = reorderingThreshold;
    return sub;
}

QuicSubheader
QuicSubheader::CreateImmediateAck(void)
{
    QuicSubheader sub;
    sub.SetFrameType(IMMEDIATE_ACK);
    return sub;
}

bool
QuicSubheader::IsAckFrequency() const
{
    return m_frameType == ACK_FREQUENCY;
}

bool
QuicSubheader::IsImmediateAck() const
{
    return m_frameType == IMMEDIATE_ACK;
}

QuicSubheader
QuicSubheader::CreateHandshakeDone(void)
{
    NS_LOG_INFO("Created HandshakeDone Header");

    QuicSubheader sub;
    sub.SetFrameType(HANDSHAKE_DONE);

    return sub;
}

QuicSubheader
QuicSubheader::CreateStreamSubHeader(uint64_t streamId,
                                     uint64_t offset,
                                     uint64_t length,
                                     bool offBit,
                                     bool lengthBit,
                                     bool finBit)
{
    NS_LOG_INFO("Created Stream SubHeader");

    QuicSubheader sub;

    // RFC 9000 §19.8: STREAM base = 0x08, bits: OFF=0x04, LEN=0x02, FIN=0x01
    uint8_t frameType = 0x08 | (offBit << 2) | (lengthBit << 1) | (finBit);

    sub.SetFrameType(frameType);
    sub.SetStreamId(streamId);

    if (offBit)
    {
        sub.SetOffset(offset);
    }
    if (lengthBit)
    {
        sub.SetLength(length);
    }

    return sub;
}

bool
QuicSubheader::IsPadding() const
{
    return m_frameType == PADDING;
}

bool
QuicSubheader::IsRstStream() const
{
    return m_frameType == RESET_STREAM;
}

bool
QuicSubheader::IsConnectionClose() const
{
    return m_frameType == CONNECTION_CLOSE;
}

bool
QuicSubheader::IsApplicationClose() const
{
    return m_frameType == CONNECTION_CLOSE_APP;
}

bool
QuicSubheader::IsMaxData() const
{
    return m_frameType == MAX_DATA;
}

bool
QuicSubheader::IsMaxStreamData() const
{
    return m_frameType == MAX_STREAM_DATA;
}

bool
QuicSubheader::IsMaxStreamId() const
{
    return m_frameType == MAX_STREAMS_BIDI || m_frameType == MAX_STREAMS_UNI;
}

bool
QuicSubheader::IsPing() const
{
    return m_frameType == PING;
}

bool
QuicSubheader::IsBlocked() const
{
    return m_frameType == DATA_BLOCKED;
}

bool
QuicSubheader::IsStreamBlocked() const
{
    return m_frameType == STREAM_DATA_BLOCKED;
}

bool
QuicSubheader::IsStreamIdBlocked() const
{
    return m_frameType == STREAMS_BLOCKED_BIDI || m_frameType == STREAMS_BLOCKED_UNI;
}

bool
QuicSubheader::IsNewConnectionId() const
{
    return m_frameType == NEW_CONNECTION_ID;
}

bool
QuicSubheader::IsStopSending() const
{
    return m_frameType == STOP_SENDING;
}

bool
QuicSubheader::IsAck() const
{
    return m_frameType == ACK;
}

bool
QuicSubheader::IsPathChallenge() const
{
    return m_frameType == PATH_CHALLENGE;
}

bool
QuicSubheader::IsPathResponse() const
{
    return m_frameType == PATH_RESPONSE;
}

bool
QuicSubheader::IsStream() const
{
    // RFC 9000 §19.8: STREAM variants occupy 0x08–0x0f
    return m_frameType >= STREAM and m_frameType <= STREAM_OFF_LEN_FIN;
}

bool
QuicSubheader::IsStreamFin() const
{
    return m_frameType & 0b00000001;
}

uint32_t
QuicSubheader::GetAckBlockCount() const
{
    return m_ackBlockCount;
}

void
QuicSubheader::SetAckBlockCount(uint32_t ackBlockCount)
{
    m_ackBlockCount = ackBlockCount;
}

const std::vector<uint32_t>&
QuicSubheader::GetAdditionalAckBlocks() const
{
    return m_additionalAckBlocks;
}

void
QuicSubheader::SetAdditionalAckBlocks(const std::vector<uint32_t>& ackBlocks)
{
    m_additionalAckBlocks = ackBlocks;
}

uint64_t
QuicSubheader::GetAckDelay() const
{
    return m_ackDelay;
}

void
QuicSubheader::SetAckDelay(uint64_t ackDelay)
{
    m_ackDelay = ackDelay;
}

uint64_t
QuicSubheader::GetConnectionId() const
{
    return m_connectionId;
}

void
QuicSubheader::SetConnectionId(uint64_t connectionId)
{
    m_connectionId = connectionId;
}

uint64_t
QuicSubheader::GetData() const
{
    return m_data;
}

void
QuicSubheader::SetData(uint64_t data)
{
    m_data = data;
}

uint16_t
QuicSubheader::GetErrorCode() const
{
    return m_errorCode;
}

void
QuicSubheader::SetErrorCode(uint16_t errorCode)
{
    m_errorCode = errorCode;
}

uint8_t
QuicSubheader::GetFrameType() const
{
    return m_frameType;
}

void
QuicSubheader::SetFrameType(uint8_t frameType)
{
    m_frameType = frameType;
}

const std::vector<uint32_t>&
QuicSubheader::GetGaps() const
{
    return m_gaps;
}

void
QuicSubheader::SetGaps(const std::vector<uint32_t>& gaps)
{
    m_gaps = gaps;
}

uint32_t
QuicSubheader::GetLargestAcknowledged() const
{
    return m_largestAcknowledged;
}

void
QuicSubheader::SetLargestAcknowledged(uint32_t largestAcknowledged)
{
    m_largestAcknowledged = largestAcknowledged;
}

uint64_t
QuicSubheader::GetEct0Count() const
{
    return m_ect0Count;
}

uint64_t
QuicSubheader::GetEct1Count() const
{
    return m_ect1Count;
}

uint64_t
QuicSubheader::GetEcnCeCount() const
{
    return m_ecnCeCount;
}

uint64_t
QuicSubheader::GetLength() const
{
    return m_length;
}

void
QuicSubheader::SetLength(uint64_t length)
{
    m_length = length;
}

uint64_t
QuicSubheader::GetMaxData() const
{
    return m_maxData;
}

void
QuicSubheader::SetMaxData(uint64_t maxData)
{
    m_maxData = maxData;
}

uint64_t
QuicSubheader::GetMaxStreamData() const
{
    return m_maxStreamData;
}

void
QuicSubheader::SetMaxStreamData(uint64_t maxStreamData)
{
    m_maxStreamData = maxStreamData;
}

uint64_t
QuicSubheader::GetMaxStreamId() const
{
    return m_maxStreamId;
}

void
QuicSubheader::SetMaxStreamId(uint64_t maxStreamId)
{
    m_maxStreamId = maxStreamId;
}

uint64_t
QuicSubheader::GetOffset() const
{
    return m_offset;
}

void
QuicSubheader::SetOffset(uint64_t offset)
{
    m_offset = offset;
}

const std::vector<uint8_t>&
QuicSubheader::GetReasonPhrase() const
{
    return m_reasonPhrase;
}

void
QuicSubheader::SetReasonPhrase(const std::vector<uint8_t>& reasonPhrase)
{
    m_reasonPhrase = reasonPhrase;
}

uint64_t
QuicSubheader::GetReasonPhraseLength() const
{
    return m_reasonPhraseLength;
}

void
QuicSubheader::SetReasonPhraseLength(uint64_t reasonPhraseLength)
{
    m_reasonPhraseLength = reasonPhraseLength;
}

uint64_t
QuicSubheader::GetSequence() const
{
    return m_sequence;
}

void
QuicSubheader::SetSequence(uint64_t sequence)
{
    m_sequence = sequence;
}

uint64_t
QuicSubheader::GetStreamId() const
{
    return m_streamId;
}

void
QuicSubheader::SetStreamId(uint64_t streamId)
{
    m_streamId = streamId;
}

// uint128_t QuicSubheader::getStatelessResetToken() const {
//	return m_statelessResetToken;
// }
//
// void QuicSubheader::SetStatelessResetToken(uint128_t statelessResetToken) {
//	m_statelessResetToken = statelessResetToken;
// }

uint64_t
QuicSubheader::GetFirstAckBlock() const
{
    return m_firstAckBlock;
}

void
QuicSubheader::SetFirstAckBlock(uint64_t firstAckBlock)
{
    m_firstAckBlock = firstAckBlock;
}

} // namespace ns3
