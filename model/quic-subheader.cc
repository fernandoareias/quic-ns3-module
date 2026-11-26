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
      m_connectionId(),
      m_largestAcknowledged(0),
      m_ackDelay(0),
      m_ackBlockCount(0),
      m_firstAckBlock(0),
      m_data(0),
      m_length(0)
{
    m_reasonPhrase = std::vector<uint8_t>();
    m_additionalAckBlocks = std::vector<uint64_t>();
    m_gaps = std::vector<uint64_t>();
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

namespace
{

/** Counts the bytes a frame writes: the size of a frame is what it serializes to. */
class SizeWriter
{
  public:
    void U8(uint8_t)
    {
        ++m_size;
    }

    void U64(uint64_t)
    {
        m_size += 8;
    }

    void VarInt(uint64_t value)
    {
        m_size += QuicVarIntLength(value);
    }

    void Bytes(const uint8_t*, uint32_t count)
    {
        m_size += count;
    }

    uint32_t Size() const
    {
        return m_size;
    }

  private:
    uint32_t m_size{0}; //!< bytes written so far
};

/** Writes a frame into a buffer. */
class BufferWriter
{
  public:
    explicit BufferWriter(Buffer::Iterator& i)
        : m_i(i)
    {
    }

    void U8(uint8_t value)
    {
        m_i.WriteU8(value);
    }

    void U64(uint64_t value)
    {
        m_i.WriteHtonU64(value);
    }

    void VarInt(uint64_t value)
    {
        QuicWriteVarInt(m_i, value);
    }

    void Bytes(const uint8_t* bytes, uint32_t count)
    {
        m_i.Write(bytes, count);
    }

  private:
    Buffer::Iterator& m_i; //!< where the frame goes
};

/** Reads a frame and never goes past the bytes that are left. */
class FrameReader
{
  public:
    explicit FrameReader(Buffer::Iterator start)
        : m_i(start),
          m_total(start.GetRemainingSize()),
          m_left(m_total)
    {
    }

    bool U8(uint8_t& value)
    {
        if (m_left < 1)
        {
            return false;
        }
        value = m_i.ReadU8();
        --m_left;
        return true;
    }

    bool U64(uint64_t& value)
    {
        if (m_left < 8)
        {
            return false;
        }
        value = m_i.ReadNtohU64();
        m_left -= 8;
        return true;
    }

    bool VarInt(uint64_t& value, uint32_t* length = nullptr)
    {
        if (m_left < 1)
        {
            return false;
        }
        Buffer::Iterator peek = m_i;
        const uint32_t size = 1U << (peek.ReadU8() >> 6);
        if (m_left < size)
        {
            return false;
        }
        value = QuicReadVarInt(m_i);
        m_left -= size;
        if (length != nullptr)
        {
            *length = size;
        }
        return true;
    }

    bool Bytes(std::vector<uint8_t>& out, uint64_t count)
    {
        if (count > m_left)
        {
            return false;
        }
        out.resize(count);
        for (uint64_t k = 0; k < count; ++k)
        {
            out[k] = m_i.ReadU8();
        }
        m_left -= count;
        return true;
    }

    /** Skip the zero bytes that follow: a run of PADDING frames is one frame. */
    void SkipZeros()
    {
        while (m_left > 0)
        {
            Buffer::Iterator peek = m_i;
            if (peek.ReadU8() != 0)
            {
                break;
            }
            m_i.ReadU8();
            --m_left;
        }
    }

    uint32_t Left() const
    {
        return m_left;
    }

    uint32_t Total() const
    {
        return m_total;
    }

    uint32_t Consumed() const
    {
        return m_total - m_left;
    }

  private:
    Buffer::Iterator m_i; //!< position
    uint32_t m_total;     //!< bytes at the start
    uint32_t m_left;      //!< bytes left
};

} // namespace

template <typename Writer>
void
QuicSubheader::Encode(Writer& w) const
{
    w.VarInt(m_frameType);

    switch (m_frameType)
    {
    case PADDING:
    case PING:
    case HANDSHAKE_DONE:
    case IMMEDIATE_ACK:
        break;

    case RESET_STREAM: // RFC 9000 Section 19.4
        w.VarInt(m_streamId);
        w.VarInt(m_errorCode);
        w.VarInt(m_offset); // Final Size
        break;

    case STOP_SENDING: // RFC 9000 Section 19.5
        w.VarInt(m_streamId);
        w.VarInt(m_errorCode);
        break;

    case CRYPTO: // RFC 9000 Section 19.6: the data follows in the packet
        w.VarInt(m_offset);
        w.VarInt(m_length);
        break;

    case NEW_TOKEN: // RFC 9000 Section 19.7
        w.VarInt(m_token.size());
        w.Bytes(m_token.data(), m_token.size());
        break;

    case CONNECTION_CLOSE:     // RFC 9000 Section 19.19: error code, frame type, reason
    case CONNECTION_CLOSE_APP: // error code, reason
        w.VarInt(m_errorCode);
        if (m_frameType == CONNECTION_CLOSE)
        {
            w.VarInt(m_triggerFrameType);
        }
        w.VarInt(m_reasonPhraseLength);
        w.Bytes(m_reasonPhrase.data(), m_reasonPhrase.size());
        break;

    case MAX_DATA:
        w.VarInt(m_maxData);
        break;

    case MAX_STREAM_DATA:
        w.VarInt(m_streamId);
        w.VarInt(m_maxStreamData);
        break;

    case MAX_STREAMS_BIDI:
    case MAX_STREAMS_UNI:
        w.VarInt(m_maxStreamId);
        break;

    case DATA_BLOCKED:
        w.VarInt(m_offset);
        break;

    case STREAM_DATA_BLOCKED:
        w.VarInt(m_streamId);
        w.VarInt(m_offset);
        break;

    case STREAMS_BLOCKED_BIDI:
    case STREAMS_BLOCKED_UNI:
        w.VarInt(m_streamId);
        break;

    case NEW_CONNECTION_ID: // RFC 9000 Section 19.15
        w.VarInt(m_sequence);
        w.VarInt(m_retirePriorTo);
        w.U8(m_connectionId.GetLength());
        w.Bytes(m_connectionId.GetBytes(), m_connectionId.GetLength());
        w.U64(m_resetTokenHi);
        w.U64(m_resetTokenLo);
        break;

    case RETIRE_CONNECTION_ID:
        w.VarInt(m_sequence);
        break;

    case PATH_CHALLENGE:
    case PATH_RESPONSE:
        w.U64(m_data); // 8 bytes of opaque data
        break;

    case ACK_FREQUENCY:
        w.VarInt(m_ackFreqSeq);
        w.VarInt(m_ackFreqThreshold);
        w.VarInt(m_ackFreqMaxDelayUs);
        w.VarInt(m_ackFreqReordering);
        break;

    case ACK: // RFC 9000 Section 19.3
    case ACK_ECN:
        w.VarInt(m_largestAcknowledged);
        w.VarInt(m_ackDelay);
        w.VarInt(m_ackBlockCount);
        for (uint64_t v : AckWireRanges())
        {
            w.VarInt(v);
        }
        if (m_frameType == ACK_ECN)
        {
            w.VarInt(m_ect0Count);
            w.VarInt(m_ect1Count);
            w.VarInt(m_ecnCeCount);
        }
        break;

    default: // STREAM, 0x08 to 0x0f (RFC 9000 Section 19.8)
        NS_ABORT_MSG_UNLESS(m_frameType >= STREAM && m_frameType <= STREAM_OFF_LEN_FIN,
                            "cannot serialize a frame of type " << m_frameType);
        w.VarInt(m_streamId);
        if (m_frameType & 0x04)
        {
            w.VarInt(m_offset);
        }
        if (m_frameType & 0x02)
        {
            w.VarInt(m_length);
        }
        break;
    }
}

uint32_t
QuicSubheader::GetSerializedSize(void) const
{
    SizeWriter writer;
    Encode(writer);
    return writer.Size();
}

uint32_t
QuicSubheader::CalculateSubHeaderLength() const
{
    return GetSerializedSize();
}

void
QuicSubheader::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this << m_frameType);
    Buffer::Iterator i = start;
    BufferWriter writer(i);
    Encode(writer);
}

uint32_t
QuicSubheader::Deserialize(Buffer::Iterator start)
{
    FrameReader r(start);
    m_valid = true;
    m_parseError = 0;
    m_offset = 0;
    m_length = 0;
    m_token.clear();
    m_reasonPhrase.clear();

    // the frame is malformed: nothing behind it in the packet can be read
    auto fail = [&](uint64_t error) {
        m_valid = false;
        m_parseError = error;
        return r.Total();
    };

    uint32_t typeLength = 0;
    if (!r.VarInt(m_frameType, &typeLength))
    {
        return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
    }
    NS_LOG_FUNCTION(this << m_frameType);
    if (typeLength > QuicVarIntLength(m_frameType))
    {
        // RFC 9000 Section 12.4: a frame type uses its shortest encoding
        return fail(TransportErrorCodes_t::PROTOCOL_VIOLATION);
    }

    switch (m_frameType)
    {
    case PADDING:
        r.SkipZeros();
        break;

    case PING:
    case HANDSHAKE_DONE:
    case IMMEDIATE_ACK:
        break;

    case RESET_STREAM:
        if (!r.VarInt(m_streamId) || !r.VarInt(m_errorCode) || !r.VarInt(m_offset))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case STOP_SENDING:
        if (!r.VarInt(m_streamId) || !r.VarInt(m_errorCode))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case CRYPTO:
        if (!r.VarInt(m_offset) || !r.VarInt(m_length))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case NEW_TOKEN: {
        uint64_t tokenLength = 0;
        // RFC 9000 Section 19.7: a token is not empty
        if (!r.VarInt(tokenLength) || tokenLength == 0 || !r.Bytes(m_token, tokenLength))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;
    }

    case CONNECTION_CLOSE:
    case CONNECTION_CLOSE_APP:
        if (!r.VarInt(m_errorCode) ||
            (m_frameType == CONNECTION_CLOSE && !r.VarInt(m_triggerFrameType)) ||
            !r.VarInt(m_reasonPhraseLength) || !r.Bytes(m_reasonPhrase, m_reasonPhraseLength))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case MAX_DATA:
        if (!r.VarInt(m_maxData))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case MAX_STREAM_DATA:
        if (!r.VarInt(m_streamId) || !r.VarInt(m_maxStreamData))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case MAX_STREAMS_BIDI:
    case MAX_STREAMS_UNI:
        if (!r.VarInt(m_maxStreamId))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case DATA_BLOCKED:
        if (!r.VarInt(m_offset))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case STREAM_DATA_BLOCKED:
        if (!r.VarInt(m_streamId) || !r.VarInt(m_offset))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case STREAMS_BLOCKED_BIDI:
    case STREAMS_BLOCKED_UNI:
        if (!r.VarInt(m_streamId))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case NEW_CONNECTION_ID: {
        uint8_t cidLength = 0;
        std::vector<uint8_t> cid;
        if (!r.VarInt(m_sequence) || !r.VarInt(m_retirePriorTo) || !r.U8(cidLength) ||
            cidLength < 1 || cidLength > QuicConnectionId::MAX_LENGTH || !r.Bytes(cid, cidLength) ||
            !r.U64(m_resetTokenHi) || !r.U64(m_resetTokenLo))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        m_connectionId = QuicConnectionId(cid.data(), cidLength);
        break;
    }

    case RETIRE_CONNECTION_ID:
        if (!r.VarInt(m_sequence))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case PATH_CHALLENGE:
    case PATH_RESPONSE:
        if (!r.U64(m_data))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case ACK_FREQUENCY:
        if (!r.VarInt(m_ackFreqSeq) || !r.VarInt(m_ackFreqThreshold) ||
            !r.VarInt(m_ackFreqMaxDelayUs) || !r.VarInt(m_ackFreqReordering))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;

    case ACK:
    case ACK_ECN: {
        uint64_t count = 0;
        uint64_t firstRange = 0;
        if (!r.VarInt(m_largestAcknowledged) || !r.VarInt(m_ackDelay) || !r.VarInt(count) ||
            !r.VarInt(firstRange) || firstRange > m_largestAcknowledged || count > r.Left())
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        // the inverse of AckWireRanges (): from counts back to absolute packet numbers
        m_ackBlockCount = count;
        m_gaps.clear();
        m_additionalAckBlocks.clear();
        uint64_t lo = m_largestAcknowledged - firstRange;
        for (uint64_t k = 0; k < count; ++k)
        {
            uint64_t gap = 0;
            uint64_t length = 0;
            if (!r.VarInt(gap) || !r.VarInt(length) || gap > lo || lo - gap < 2 ||
                length > lo - gap - 2)
            {
                return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
            }
            const uint64_t hi = lo - gap - 2;
            m_gaps.push_back(lo > 0 ? lo - 1 : 0);
            m_additionalAckBlocks.push_back(hi);
            lo = hi - length;
        }
        m_firstAckBlock = lo;
        if (m_frameType == ACK_ECN &&
            (!r.VarInt(m_ect0Count) || !r.VarInt(m_ect1Count) || !r.VarInt(m_ecnCeCount)))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;
    }

    default:
        if (m_frameType < STREAM || m_frameType > STREAM_OFF_LEN_FIN)
        {
            // RFC 9000 Section 12.4: a frame of an unknown type is a FRAME_ENCODING_ERROR
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        if (!r.VarInt(m_streamId) || ((m_frameType & 0x04) && !r.VarInt(m_offset)) ||
            ((m_frameType & 0x02) && !r.VarInt(m_length)))
        {
            return fail(TransportErrorCodes_t::FRAME_ENCODING_ERROR);
        }
        break;
    }

    return r.Consumed();
}

void
QuicSubheader::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this << (uint64_t)m_frameType);

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
                               uint64_t applicationErrorCode,
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
QuicSubheader::CreateConnectionClose(uint64_t errorCode, const char* reasonPhrase)
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
QuicSubheader::CreateApplicationClose(uint64_t errorCode, const char* reasonPhrase)
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
QuicSubheader::CreateNewConnectionId(
    uint64_t sequence,
    const QuicConnectionId& connectionId) // uint128_t statelessResetToken);
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
                                     const QuicConnectionId& connectionId,
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
QuicSubheader::CreateStopSending(uint64_t streamId, uint64_t applicationErrorCode)
{
    NS_LOG_INFO("Created StopSending Header");

    QuicSubheader sub;
    sub.SetFrameType(STOP_SENDING);
    sub.SetStreamId(streamId);
    sub.SetErrorCode(applicationErrorCode);

    return sub;
}

QuicSubheader
QuicSubheader::CreateAck(uint64_t largestAcknowledged,
                         uint64_t ackDelay,
                         uint64_t firstAckBlock,
                         std::vector<uint64_t>& gaps,
                         std::vector<uint64_t>& additionalAckBlocks)
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
    return m_frameType == ACK || m_frameType == ACK_ECN;
}

void
QuicSubheader::SetEcnCounts(uint64_t ect0, uint64_t ect1, uint64_t ce)
{
    m_frameType = ACK_ECN;
    m_ect0Count = ect0;
    m_ect1Count = ect1;
    m_ecnCeCount = ce;
}

bool
QuicSubheader::HasLengthField() const
{
    return m_frameType == CRYPTO || (IsStream() && (m_frameType & 0x02));
}

uint64_t
QuicSubheader::GetPayloadLength(uint64_t remaining) const
{
    if (IsStream())
    {
        return (m_frameType & 0x02) ? m_length : remaining;
    }
    return m_frameType == CRYPTO ? m_length : 0;
}

QuicSubheader
QuicSubheader::CreateCrypto(uint64_t offset, uint64_t length)
{
    QuicSubheader sub;
    sub.SetFrameType(CRYPTO);
    sub.m_offset = offset;
    sub.m_length = length;
    return sub;
}

QuicSubheader
QuicSubheader::CreateNewToken(const std::vector<uint8_t>& token)
{
    QuicSubheader sub;
    sub.SetFrameType(NEW_TOKEN);
    sub.m_token = token;
    return sub;
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

uint64_t
QuicSubheader::GetAckBlockCount() const
{
    return m_ackBlockCount;
}

void
QuicSubheader::SetAckBlockCount(uint64_t ackBlockCount)
{
    m_ackBlockCount = ackBlockCount;
}

const std::vector<uint64_t>&
QuicSubheader::GetAdditionalAckBlocks() const
{
    return m_additionalAckBlocks;
}

void
QuicSubheader::SetAdditionalAckBlocks(const std::vector<uint64_t>& ackBlocks)
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

QuicConnectionId
QuicSubheader::GetConnectionId() const
{
    return m_connectionId;
}

void
QuicSubheader::SetConnectionId(const QuicConnectionId& connectionId)
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

uint64_t
QuicSubheader::GetErrorCode() const
{
    return m_errorCode;
}

void
QuicSubheader::SetErrorCode(uint64_t errorCode)
{
    m_errorCode = errorCode;
}

uint64_t
QuicSubheader::GetFrameType() const
{
    return m_frameType;
}

void
QuicSubheader::SetFrameType(uint64_t frameType)
{
    m_frameType = frameType;
}

const std::vector<uint64_t>&
QuicSubheader::GetGaps() const
{
    return m_gaps;
}

void
QuicSubheader::SetGaps(const std::vector<uint64_t>& gaps)
{
    m_gaps = gaps;
}

uint64_t
QuicSubheader::GetLargestAcknowledged() const
{
    return m_largestAcknowledged;
}

void
QuicSubheader::SetLargestAcknowledged(uint64_t largestAcknowledged)
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
