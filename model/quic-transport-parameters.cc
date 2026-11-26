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

#include "quic-transport-parameters.h"

#include "quic-wire.h"

#include "ns3/log.h"

#include <iostream>
#include <set>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicTransportParameters");

NS_OBJECT_ENSURE_REGISTERED(QuicTransportParameters);

namespace
{

/**
 * Append a variable-length integer to bytes.
 *
 * @param out the bytes.
 * @param value the value.
 */
void
AppendVarInt(std::vector<uint8_t>& out, uint64_t value)
{
    const uint32_t length = QuicVarIntLength(value);
    const uint8_t prefix = length == 1 ? 0x00 : length == 2 ? 0x40 : length == 4 ? 0x80 : 0xC0;
    for (uint32_t k = 0; k < length; ++k)
    {
        uint8_t byte = static_cast<uint8_t>(value >> (8 * (length - 1 - k)));
        out.push_back(k == 0 ? (byte | prefix) : byte);
    }
}

/**
 * Append an entry whose value is a variable-length integer.
 *
 * @param out the bytes.
 * @param id the identifier.
 * @param value the value.
 */
void
AppendVarIntEntry(std::vector<uint8_t>& out, uint64_t id, uint64_t value)
{
    AppendVarInt(out, id);
    AppendVarInt(out, QuicVarIntLength(value));
    AppendVarInt(out, value);
}

/**
 * Append an entry whose value is bytes.
 *
 * @param out the bytes.
 * @param id the identifier.
 * @param value the bytes.
 */
void
AppendBytesEntry(std::vector<uint8_t>& out, uint64_t id, const std::vector<uint8_t>& value)
{
    AppendVarInt(out, id);
    AppendVarInt(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

/**
 * Read the value of a parameter that is a variable-length integer.
 *
 * @param bytes the bytes of the value.
 * @param value set to the value.
 * @return false when the bytes are not exactly one integer.
 */
bool
DecodeVarInt(const std::vector<uint8_t>& bytes, uint64_t& value)
{
    if (bytes.empty() || bytes.size() != (1U << (bytes[0] >> 6)))
    {
        return false;
    }
    value = bytes[0] & 0x3F;
    for (size_t k = 1; k < bytes.size(); ++k)
    {
        value = (value << 8) | bytes[k];
    }
    return true;
}

/**
 * Read a connection id from the value of a parameter.
 *
 * @param bytes the bytes of the value.
 * @param cid set to the id.
 * @return false when the bytes are longer than a connection id.
 */
bool
DecodeConnectionId(const std::vector<uint8_t>& bytes, QuicConnectionId& cid)
{
    if (bytes.size() > QuicConnectionId::MAX_LENGTH)
    {
        return false;
    }
    cid = QuicConnectionId(bytes.data(), static_cast<uint8_t>(bytes.size()));
    return true;
}

} // namespace

QuicTransportParameters::QuicTransportParameters()
{
}

QuicTransportParameters::~QuicTransportParameters()
{
}

TypeId
QuicTransportParameters::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicTransportParameters")
                            .SetParent<Header>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicTransportParameters>();
    return tid;
}

TypeId
QuicTransportParameters::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

void
QuicTransportParameters::ResetToDefaults()
{
    m_initial_max_stream_data = 0;
    m_initial_max_data = 0;
    m_initial_max_stream_id_bidi = 0;
    m_idleTimeout = 0;
    m_max_udp_payload_size = 65527;
    m_stateless_reset_token_hi = 0;
    m_stateless_reset_token_lo = 0;
    m_ack_delay_exponent = 3;
    m_initial_max_stream_id_uni = 0;
    m_initial_max_stream_data_bidi_remote = 0;
    m_initial_max_stream_data_uni = 0;
    m_min_ack_delay = 0;
    m_max_ack_delay = 25;
    m_active_connection_id_limit = 2;
    m_disable_active_migration = 0;
    m_initial_source_connection_id = QuicConnectionId();
    m_original_destination_connection_id = QuicConnectionId();
    m_retry_source_connection_id = QuicConnectionId();
    m_raw.clear();
}

std::vector<uint8_t>
QuicTransportParameters::EncodeEntries() const
{
    std::vector<uint8_t> out;
    auto cidBytes = [](const QuicConnectionId& cid) {
        return std::vector<uint8_t>(cid.GetBytes(), cid.GetBytes() + cid.GetLength());
    };

    if (!m_original_destination_connection_id.IsEmpty())
    {
        AppendBytesEntry(out,
                         ORIGINAL_DESTINATION_CONNECTION_ID,
                         cidBytes(m_original_destination_connection_id));
    }
    if (m_idleTimeout != 0)
    {
        AppendVarIntEntry(out, MAX_IDLE_TIMEOUT, m_idleTimeout);
    }
    if (m_stateless_reset_token_hi != 0 || m_stateless_reset_token_lo != 0)
    {
        std::vector<uint8_t> token(16);
        for (uint32_t k = 0; k < 8; ++k)
        {
            token[k] = static_cast<uint8_t>(m_stateless_reset_token_hi >> (56 - 8 * k));
            token[8 + k] = static_cast<uint8_t>(m_stateless_reset_token_lo >> (56 - 8 * k));
        }
        AppendBytesEntry(out, STATELESS_RESET_TOKEN, token);
    }
    if (m_max_udp_payload_size != 65527)
    {
        AppendVarIntEntry(out, MAX_UDP_PAYLOAD_SIZE, m_max_udp_payload_size);
    }
    if (m_initial_max_data != 0)
    {
        AppendVarIntEntry(out, INITIAL_MAX_DATA, m_initial_max_data);
    }
    if (m_initial_max_stream_data != 0)
    {
        AppendVarIntEntry(out, INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, m_initial_max_stream_data);
    }
    if (m_initial_max_stream_data_bidi_remote != 0)
    {
        AppendVarIntEntry(out,
                          INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                          m_initial_max_stream_data_bidi_remote);
    }
    if (m_initial_max_stream_data_uni != 0)
    {
        AppendVarIntEntry(out, INITIAL_MAX_STREAM_DATA_UNI, m_initial_max_stream_data_uni);
    }
    if (m_initial_max_stream_id_bidi != 0)
    {
        AppendVarIntEntry(out, INITIAL_MAX_STREAMS_BIDI, m_initial_max_stream_id_bidi);
    }
    if (m_initial_max_stream_id_uni != 0)
    {
        AppendVarIntEntry(out, INITIAL_MAX_STREAMS_UNI, m_initial_max_stream_id_uni);
    }
    if (m_ack_delay_exponent != 3)
    {
        AppendVarIntEntry(out, ACK_DELAY_EXPONENT, m_ack_delay_exponent);
    }
    if (m_max_ack_delay != 25)
    {
        AppendVarIntEntry(out, MAX_ACK_DELAY, m_max_ack_delay);
    }
    if (m_disable_active_migration != 0)
    {
        AppendBytesEntry(out, DISABLE_ACTIVE_MIGRATION, {});
    }
    if (m_active_connection_id_limit != 2)
    {
        AppendVarIntEntry(out, ACTIVE_CONNECTION_ID_LIMIT, m_active_connection_id_limit);
    }
    if (!m_initial_source_connection_id.IsEmpty())
    {
        AppendBytesEntry(out,
                         INITIAL_SOURCE_CONNECTION_ID,
                         cidBytes(m_initial_source_connection_id));
    }
    if (!m_retry_source_connection_id.IsEmpty())
    {
        AppendBytesEntry(out, RETRY_SOURCE_CONNECTION_ID, cidBytes(m_retry_source_connection_id));
    }
    if (m_min_ack_delay != 0)
    {
        AppendVarIntEntry(out, MIN_ACK_DELAY, m_min_ack_delay);
    }
    for (const auto& raw : m_raw)
    {
        AppendBytesEntry(out, raw.first, raw.second);
    }
    return out;
}

uint32_t
QuicTransportParameters::GetSerializedSize(void) const
{
    const uint32_t body = EncodeEntries().size();
    return QuicVarIntLength(body) + body;
}

void
QuicTransportParameters::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this);
    const std::vector<uint8_t> body = EncodeEntries();
    Buffer::Iterator i = start;
    QuicWriteVarInt(i, body.size());
    i.Write(body.data(), body.size());
}

uint32_t
QuicTransportParameters::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this);
    ResetToDefaults();
    m_valid = true;

    Buffer::Iterator i = start;
    const uint32_t total = start.GetRemainingSize();
    uint32_t left = total;

    // every read stays inside the bytes of the list
    auto readVarInt = [&](uint64_t& value, uint32_t& budget) {
        if (budget < 1)
        {
            return false;
        }
        Buffer::Iterator peek = i;
        const uint32_t size = 1U << (peek.ReadU8() >> 6);
        if (budget < size)
        {
            return false;
        }
        value = QuicReadVarInt(i);
        budget -= size;
        left -= size;
        return true;
    };

    uint64_t length = 0;
    uint32_t lengthBudget = left;
    if (!readVarInt(length, lengthBudget) || length > left)
    {
        m_valid = false;
        return total;
    }
    uint32_t budget = static_cast<uint32_t>(length);
    const uint32_t consumed = total - left + budget;

    std::set<uint64_t> seen;
    while (budget > 0)
    {
        uint64_t id = 0;
        uint64_t size = 0;
        if (!readVarInt(id, budget) || !readVarInt(size, budget) || size > budget)
        {
            m_valid = false;
            break;
        }
        std::vector<uint8_t> value(size);
        for (uint64_t k = 0; k < size; ++k)
        {
            value[k] = i.ReadU8();
        }
        budget -= size;
        left -= size;

        // RFC 9000 Section 7.4: a parameter that is repeated is an error
        if (!seen.insert(id).second)
        {
            m_valid = false;
            continue;
        }

        uint64_t number = 0;
        const bool isNumber = DecodeVarInt(value, number);
        bool ok = true;
        switch (id)
        {
        case ORIGINAL_DESTINATION_CONNECTION_ID:
            ok = DecodeConnectionId(value, m_original_destination_connection_id);
            break;
        case MAX_IDLE_TIMEOUT:
            ok = isNumber;
            m_idleTimeout = number;
            break;
        case STATELESS_RESET_TOKEN:
            ok = value.size() == 16;
            if (ok)
            {
                for (uint32_t k = 0; k < 8; ++k)
                {
                    m_stateless_reset_token_hi = (m_stateless_reset_token_hi << 8) | value[k];
                    m_stateless_reset_token_lo = (m_stateless_reset_token_lo << 8) | value[8 + k];
                }
            }
            break;
        case MAX_UDP_PAYLOAD_SIZE:
            ok = isNumber && number >= 1200;
            m_max_udp_payload_size = number;
            break;
        case INITIAL_MAX_DATA:
            ok = isNumber;
            m_initial_max_data = number;
            break;
        case INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            ok = isNumber;
            m_initial_max_stream_data = number;
            break;
        case INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            ok = isNumber;
            m_initial_max_stream_data_bidi_remote = number;
            break;
        case INITIAL_MAX_STREAM_DATA_UNI:
            ok = isNumber;
            m_initial_max_stream_data_uni = number;
            break;
        case INITIAL_MAX_STREAMS_BIDI:
            // RFC 9000 Section 4.6: a limit above 2^60 is an error
            ok = isNumber && number <= (1ULL << 60);
            m_initial_max_stream_id_bidi = number;
            break;
        case INITIAL_MAX_STREAMS_UNI:
            ok = isNumber && number <= (1ULL << 60);
            m_initial_max_stream_id_uni = number;
            break;
        case ACK_DELAY_EXPONENT:
            ok = isNumber && number <= 20;
            m_ack_delay_exponent = static_cast<uint8_t>(number);
            break;
        case MAX_ACK_DELAY:
            ok = isNumber && number < (1ULL << 14);
            m_max_ack_delay = number;
            break;
        case DISABLE_ACTIVE_MIGRATION:
            ok = value.empty();
            m_disable_active_migration = 1;
            break;
        case ACTIVE_CONNECTION_ID_LIMIT:
            ok = isNumber && number >= 2;
            m_active_connection_id_limit = number;
            break;
        case INITIAL_SOURCE_CONNECTION_ID:
            ok = DecodeConnectionId(value, m_initial_source_connection_id);
            break;
        case RETRY_SOURCE_CONNECTION_ID:
            ok = DecodeConnectionId(value, m_retry_source_connection_id);
            break;
        case MIN_ACK_DELAY:
            ok = isNumber;
            m_min_ack_delay = number;
            break;
        default:
            // RFC 9000 Section 7.4.2: a parameter that is not known is ignored
            m_raw[id] = value;
            break;
        }
        if (!ok)
        {
            m_valid = false;
        }
    }
    if (budget > 0)
    {
        // the list ended inside an entry: skip what is left of it
        m_valid = false;
        for (; budget > 0; --budget)
        {
            i.ReadU8();
            --left;
        }
    }
    return consumed;
}

void
QuicTransportParameters::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this);
    os << "|initial_max_stream_data_bidi_local " << m_initial_max_stream_data << "|\n";
    os << "|initial_max_data " << m_initial_max_data << "|\n";
    os << "|initial_max_streams_bidi " << m_initial_max_stream_id_bidi << "|\n";
    os << "|initial_max_streams_uni " << m_initial_max_stream_id_uni << "|\n";
    os << "|max_idle_timeout " << m_idleTimeout << "|\n";
    os << "|max_udp_payload_size " << m_max_udp_payload_size << "|\n";
    os << "|ack_delay_exponent " << +m_ack_delay_exponent << "|\n";
    os << "|max_ack_delay " << m_max_ack_delay << "|\n";
    os << "|active_connection_id_limit " << m_active_connection_id_limit << "|\n";
    os << "|initial_source_connection_id " << m_initial_source_connection_id << "|\n";
    os << "|original_destination_connection_id " << m_original_destination_connection_id << "]\n";
}

std::ostream&
operator<<(std::ostream& os, QuicTransportParameters& tc)
{
    tc.Print(os);
    return os;
}

QuicTransportParameters
QuicTransportParameters::CreateTransportParameters(uint64_t initial_max_stream_data,
                                                   uint64_t initial_max_data,
                                                   uint64_t initial_max_stream_id_bidi,
                                                   uint64_t idleTimeout,
                                                   uint64_t max_udp_payload_size,
                                                   uint8_t ack_delay_exponent,
                                                   uint64_t initial_max_stream_id_uni)
{
    NS_LOG_INFO("Create Transport Parameters Helper called");

    QuicTransportParameters transport;
    transport.SetInitialMaxStreamData(initial_max_stream_data);
    transport.SetInitialMaxData(initial_max_data);
    transport.SetInitialMaxStreamIdBidi(initial_max_stream_id_bidi);
    transport.SetIdleTimeout(idleTimeout);
    transport.SetMaxUdpPayloadSize(max_udp_payload_size);
    transport.SetAckDelayExponent(ack_delay_exponent);
    transport.SetInitialMaxStreamIdUni(initial_max_stream_id_uni);
    return transport;
}

bool
operator==(const QuicTransportParameters& lhs, const QuicTransportParameters& rhs)
{
    return lhs.m_initial_max_stream_data == rhs.m_initial_max_stream_data &&
           lhs.m_initial_max_data == rhs.m_initial_max_data &&
           lhs.m_initial_max_stream_id_bidi == rhs.m_initial_max_stream_id_bidi &&
           lhs.m_idleTimeout == rhs.m_idleTimeout &&
           lhs.m_max_udp_payload_size == rhs.m_max_udp_payload_size &&
           lhs.m_stateless_reset_token_hi == rhs.m_stateless_reset_token_hi &&
           lhs.m_stateless_reset_token_lo == rhs.m_stateless_reset_token_lo &&
           lhs.m_ack_delay_exponent == rhs.m_ack_delay_exponent &&
           lhs.m_initial_max_stream_id_uni == rhs.m_initial_max_stream_id_uni &&
           lhs.m_initial_max_stream_data_bidi_remote == rhs.m_initial_max_stream_data_bidi_remote &&
           lhs.m_initial_max_stream_data_uni == rhs.m_initial_max_stream_data_uni &&
           lhs.m_min_ack_delay == rhs.m_min_ack_delay && lhs.m_max_ack_delay == rhs.m_max_ack_delay &&
           lhs.m_active_connection_id_limit == rhs.m_active_connection_id_limit &&
           lhs.m_disable_active_migration == rhs.m_disable_active_migration &&
           lhs.m_initial_source_connection_id == rhs.m_initial_source_connection_id &&
           lhs.m_original_destination_connection_id == rhs.m_original_destination_connection_id &&
           lhs.m_retry_source_connection_id == rhs.m_retry_source_connection_id &&
           lhs.m_raw == rhs.m_raw;
}

void
QuicTransportParameters::SetRawParameter(uint64_t id, const std::vector<uint8_t>& value)
{
    m_raw[id] = value;
}

uint8_t
QuicTransportParameters::GetAckDelayExponent() const
{
    return m_ack_delay_exponent;
}

void
QuicTransportParameters::SetAckDelayExponent(uint8_t ackDelayExponent)
{
    m_ack_delay_exponent = ackDelayExponent;
}

uint64_t
QuicTransportParameters::GetIdleTimeout() const
{
    return m_idleTimeout;
}

void
QuicTransportParameters::SetIdleTimeout(uint64_t idleTimeout)
{
    m_idleTimeout = idleTimeout;
}

uint64_t
QuicTransportParameters::GetInitialMaxData() const
{
    return m_initial_max_data;
}

void
QuicTransportParameters::SetInitialMaxData(uint64_t initialMaxData)
{
    m_initial_max_data = initialMaxData;
}

uint64_t
QuicTransportParameters::GetInitialMaxStreamData() const
{
    return m_initial_max_stream_data;
}

void
QuicTransportParameters::SetInitialMaxStreamData(uint64_t initialMaxStreamData)
{
    m_initial_max_stream_data = initialMaxStreamData;
}

uint64_t
QuicTransportParameters::GetInitialMaxStreamDataBidiRemote() const
{
    return m_initial_max_stream_data_bidi_remote;
}

void
QuicTransportParameters::SetInitialMaxStreamDataBidiRemote(uint64_t val)
{
    m_initial_max_stream_data_bidi_remote = val;
}

uint64_t
QuicTransportParameters::GetInitialMaxStreamDataUni() const
{
    return m_initial_max_stream_data_uni;
}

void
QuicTransportParameters::SetInitialMaxStreamDataUni(uint64_t val)
{
    m_initial_max_stream_data_uni = val;
}

uint64_t
QuicTransportParameters::GetMaxAckDelay() const
{
    return m_max_ack_delay;
}

void
QuicTransportParameters::SetMaxAckDelay(uint64_t val)
{
    m_max_ack_delay = val;
}

uint64_t
QuicTransportParameters::GetMinAckDelay() const
{
    return m_min_ack_delay;
}

void
QuicTransportParameters::SetMinAckDelay(uint64_t val)
{
    m_min_ack_delay = val;
}

uint64_t
QuicTransportParameters::GetInitialMaxStreamIdBidi() const
{
    return m_initial_max_stream_id_bidi;
}

void
QuicTransportParameters::SetInitialMaxStreamIdBidi(uint64_t initialMaxStreamIdBidi)
{
    m_initial_max_stream_id_bidi = initialMaxStreamIdBidi;
}

uint64_t
QuicTransportParameters::GetInitialMaxStreamIdUni() const
{
    return m_initial_max_stream_id_uni;
}

void
QuicTransportParameters::SetInitialMaxStreamIdUni(uint64_t initialMaxStreamIdUni)
{
    m_initial_max_stream_id_uni = initialMaxStreamIdUni;
}

uint64_t
QuicTransportParameters::GetMaxUdpPayloadSize() const
{
    return m_max_udp_payload_size;
}

void
QuicTransportParameters::SetMaxUdpPayloadSize(uint64_t maxUdpPayloadSize)
{
    m_max_udp_payload_size = maxUdpPayloadSize;
}

uint64_t
QuicTransportParameters::GetStatelessResetTokenHi() const
{
    return m_stateless_reset_token_hi;
}

uint64_t
QuicTransportParameters::GetStatelessResetTokenLo() const
{
    return m_stateless_reset_token_lo;
}

void
QuicTransportParameters::SetStatelessResetToken(uint64_t hi, uint64_t lo)
{
    m_stateless_reset_token_hi = hi;
    m_stateless_reset_token_lo = lo;
}

uint64_t
QuicTransportParameters::GetActiveConnectionIdLimit() const
{
    return m_active_connection_id_limit;
}

void
QuicTransportParameters::SetActiveConnectionIdLimit(uint64_t limit)
{
    m_active_connection_id_limit = limit;
}

uint8_t
QuicTransportParameters::GetDisableActiveMigration() const
{
    return m_disable_active_migration;
}

void
QuicTransportParameters::SetDisableActiveMigration(uint8_t disable)
{
    m_disable_active_migration = disable;
}

QuicConnectionId
QuicTransportParameters::GetInitialSourceConnectionId() const
{
    return m_initial_source_connection_id;
}

void
QuicTransportParameters::SetInitialSourceConnectionId(const QuicConnectionId& cid)
{
    m_initial_source_connection_id = cid;
}

QuicConnectionId
QuicTransportParameters::GetOriginalDestinationConnectionId() const
{
    return m_original_destination_connection_id;
}

void
QuicTransportParameters::SetOriginalDestinationConnectionId(const QuicConnectionId& cid)
{
    m_original_destination_connection_id = cid;
}

QuicConnectionId
QuicTransportParameters::GetRetrySourceConnectionId() const
{
    return m_retry_source_connection_id;
}

void
QuicTransportParameters::SetRetrySourceConnectionId(const QuicConnectionId& cid)
{
    m_retry_source_connection_id = cid;
}

} // namespace ns3
