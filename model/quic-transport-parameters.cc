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

#include "ns3/address-utils.h"
#include "ns3/buffer.h"
#include "ns3/log.h"

#include <iostream>
#include <stdint.h>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicTransportParameters");

NS_OBJECT_ENSURE_REGISTERED(QuicTransportParameters);

QuicTransportParameters::QuicTransportParameters()
    : m_initial_max_stream_data(0),
      m_initial_max_data(0),
      m_initial_max_stream_id_bidi(0),
      m_idleTimeout(300000), // RFC 9000 s18.2: milliseconds; 0 disables the idle timeout
      m_omit_connection(false),
      m_max_packet_size(65527),
      m_stateless_reset_token_hi(0),
      m_stateless_reset_token_lo(0),
      m_ack_delay_exponent(3),
      m_initial_max_stream_id_uni(0),
      m_initial_max_stream_data_bidi_remote(0), // RFC 9000 §18.2, 0x06
      m_initial_max_stream_data_uni(0),         // RFC 9000 §18.2, 0x07
      m_min_ack_delay(0),
      m_max_ack_delay(25),             // RFC 9000 §18.2, 0x0b: default 25 ms
      m_active_connection_id_limit(2), // RFC 9000 §18.2: MUST be ≥2
      m_disable_active_migration(
          0), // RFC 9000 §18.2: active migration is supported (msquic default)
      m_initial_source_connection_id(0),
      m_original_destination_connection_id(0)
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

uint32_t
QuicTransportParameters::GetSerializedSize(void) const
{
    uint32_t serializesSize = CalculateHeaderLength();
    NS_LOG_INFO("Serialized Size " << serializesSize);

    return serializesSize;
}

uint32_t
QuicTransportParameters::CalculateHeaderLength() const
{
    // Fields (RFC 9000 §18.2):
    //   uint32 ×6: initial_max_stream_data(0x05), initial_max_data(0x01),
    //              initial_max_stream_id_bidi(0x08), initial_max_stream_id_uni(0x09),
    //              initial_max_stream_data_bidi_remote(0x06), initial_max_stream_data_uni(0x07)
    //   uint16 ×2: max_packet_size(0x03), max_ack_delay(0x0b)
    //   uint8  ×4: omit_connection, ack_delay_exponent(0x0a),
    //              active_connection_id_limit(0x0e), disable_active_migration(0x0c)
    //   uint32 ×2: max_idle_timeout (ms, 0x01), min_ack_delay (us), ack-frequency draft (msquic
    //   0xFF04DE1B) uint64 ×4: stateless_reset_token_hi+lo(0x02), initial_source_cid(0x0f),
    //              original_destination_cid(0x00)
    // Total: 8*32 + 2*16 + 4*8 + 4*64 = 256+32+32+256 = 576 bits = 72 bytes
    uint32_t len = 32 * 8 + 16 * 2 + 8 * 4 + 64 * 4;

    return len / 8;
}

void
QuicTransportParameters::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this);
    NS_LOG_INFO("Serialize::Serialized Size " << CalculateHeaderLength());

    Buffer::Iterator i = start;

    i.WriteHtonU32(m_initial_max_stream_data);    // 0x05 initial_max_stream_data_bidi_local
    i.WriteHtonU32(m_initial_max_data);           // 0x01 initial_max_data
    i.WriteHtonU32(m_initial_max_stream_id_bidi); // 0x08 initial_max_streams_bidi
    i.WriteHtonU32(m_initial_max_stream_id_uni);  // 0x09 initial_max_streams_uni
    i.WriteHtonU32(
        m_initial_max_stream_data_bidi_remote);    // 0x06 initial_max_stream_data_bidi_remote
    i.WriteHtonU32(m_initial_max_stream_data_uni); // 0x07 initial_max_stream_data_uni
    i.WriteHtonU32(m_min_ack_delay);               // ack-frequency min_ack_delay (us)
    i.WriteHtonU32(m_idleTimeout);                 // 0x01 max_idle_timeout (ms)
    i.WriteHtonU16(m_max_packet_size);
    i.WriteHtonU16(m_max_ack_delay); // 0x0b max_ack_delay (ms)
    i.WriteU8(m_omit_connection);
    i.WriteU8(m_ack_delay_exponent);                      // 0x0a ack_delay_exponent
    i.WriteU8(m_active_connection_id_limit);              // 0x0e active_connection_id_limit
    i.WriteU8(m_disable_active_migration);                // 0x0c disable_active_migration
    i.WriteHtonU64(m_stateless_reset_token_hi);           // 0x02 stateless_reset_token (hi 64 bits)
    i.WriteHtonU64(m_stateless_reset_token_lo);           //      stateless_reset_token (lo 64 bits)
    i.WriteHtonU64(m_initial_source_connection_id);       // 0x0f initial_source_connection_id
    i.WriteHtonU64(m_original_destination_connection_id); // 0x00 original_destination_connection_id
}

uint32_t
QuicTransportParameters::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this);

    Buffer::Iterator i = start;

    m_initial_max_stream_data = i.ReadNtohU32();
    m_initial_max_data = i.ReadNtohU32();
    m_initial_max_stream_id_bidi = i.ReadNtohU32();
    m_initial_max_stream_id_uni = i.ReadNtohU32();
    m_initial_max_stream_data_bidi_remote = i.ReadNtohU32(); // 0x06
    m_initial_max_stream_data_uni = i.ReadNtohU32();         // 0x07
    m_min_ack_delay = i.ReadNtohU32();
    m_idleTimeout = i.ReadNtohU32();
    m_max_packet_size = i.ReadNtohU16();
    m_max_ack_delay = i.ReadNtohU16(); // 0x0b
    m_omit_connection = i.ReadU8();
    m_ack_delay_exponent = i.ReadU8();
    m_active_connection_id_limit = i.ReadU8();
    m_disable_active_migration = i.ReadU8();
    m_stateless_reset_token_hi = i.ReadNtohU64();
    m_stateless_reset_token_lo = i.ReadNtohU64();
    m_initial_source_connection_id = i.ReadNtohU64();
    m_original_destination_connection_id = i.ReadNtohU64();

    NS_LOG_INFO("Deserialize::Serialized Size " << CalculateHeaderLength());

    return GetSerializedSize();
}

void
QuicTransportParameters::Print(std::ostream& os) const
{
    os << "[initial_max_stream_data_bidi_local " << m_initial_max_stream_data << "|\n";
    os << "|initial_max_data " << m_initial_max_data << "|\n";
    os << "|initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << "|\n";
    os << "|initial_max_stream_id_uni " << m_initial_max_stream_id_uni << "|\n";
    os << "|initial_max_stream_data_bidi_remote " << m_initial_max_stream_data_bidi_remote << "|\n";
    os << "|initial_max_stream_data_uni " << m_initial_max_stream_data_uni << "|\n";
    os << "|idleTimeout " << m_idleTimeout << "|\n";
    os << "|omit_connection " << (uint16_t)m_omit_connection << "|\n";
    os << "|max_packet_size " << m_max_packet_size << "|\n";
    os << "|max_ack_delay " << m_max_ack_delay << " ms|\n";
    os << "|stateless_reset_token " << m_stateless_reset_token_hi << m_stateless_reset_token_lo
       << "|\n";
    os << "|ack_delay_exponent " << (uint16_t)m_ack_delay_exponent << "|\n";
    os << "|active_connection_id_limit " << (uint16_t)m_active_connection_id_limit << "|\n";
    os << "|disable_active_migration " << (uint16_t)m_disable_active_migration << "|\n";
    os << "|initial_source_connection_id " << m_initial_source_connection_id << "|\n";
    os << "|original_destination_connection_id " << m_original_destination_connection_id << "]\n";
}

QuicTransportParameters
QuicTransportParameters::CreateTransportParameters(
    uint32_t initial_max_stream_data,
    uint32_t initial_max_data,
    uint32_t initial_max_stream_id_bidi,
    uint32_t idleTimeout,
    uint8_t omit_connection,
    uint16_t max_packet_size,
    /*uint128_t stateless_reset_token,*/ uint8_t ack_delay_exponent,
    uint32_t initial_max_stream_id_uni)
{
    NS_LOG_INFO("Create Transport Parameters Helper called");

    QuicTransportParameters transport;
    transport.SetInitialMaxStreamData(initial_max_stream_data);
    transport.SetInitialMaxData(initial_max_data);
    transport.SetInitialMaxStreamIdBidi(initial_max_stream_id_bidi);
    transport.SetIdleTimeout(idleTimeout);
    transport.SetOmitConnection(omit_connection);
    transport.SetMaxPacketSize(max_packet_size);
    // transport.SetStatelessResetToken(stateless_reset_token);
    transport.SetAckDelayExponent(ack_delay_exponent);
    transport.SetInitialMaxStreamIdUni(initial_max_stream_id_uni);

    return transport;
}

bool
operator==(const QuicTransportParameters& lhs, const QuicTransportParameters& rhs)
{
    return (
        lhs.m_initial_max_stream_data == rhs.m_initial_max_stream_data &&
        lhs.m_initial_max_data == rhs.m_initial_max_data &&
        lhs.m_initial_max_stream_id_bidi == rhs.m_initial_max_stream_id_bidi &&
        lhs.m_idleTimeout == rhs.m_idleTimeout && lhs.m_omit_connection == rhs.m_omit_connection &&
        lhs.m_max_packet_size == rhs.m_max_packet_size &&
        lhs.m_stateless_reset_token_hi == rhs.m_stateless_reset_token_hi &&
        lhs.m_stateless_reset_token_lo == rhs.m_stateless_reset_token_lo &&
        lhs.m_ack_delay_exponent == rhs.m_ack_delay_exponent &&
        lhs.m_initial_max_stream_id_uni == rhs.m_initial_max_stream_id_uni &&
        lhs.m_initial_max_stream_data_bidi_remote == rhs.m_initial_max_stream_data_bidi_remote &&
        lhs.m_initial_max_stream_data_uni == rhs.m_initial_max_stream_data_uni &&
        lhs.m_max_ack_delay == rhs.m_max_ack_delay &&
        lhs.m_active_connection_id_limit == rhs.m_active_connection_id_limit &&
        lhs.m_disable_active_migration == rhs.m_disable_active_migration &&
        lhs.m_initial_source_connection_id == rhs.m_initial_source_connection_id &&
        lhs.m_original_destination_connection_id == rhs.m_original_destination_connection_id);
}

std::ostream&
operator<<(std::ostream& os, QuicTransportParameters& tc)
{
    tc.Print(os);
    return os;
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

uint32_t
QuicTransportParameters::GetIdleTimeout() const
{
    return m_idleTimeout;
}

void
QuicTransportParameters::SetIdleTimeout(uint32_t idleTimeout)
{
    m_idleTimeout = idleTimeout;
}

uint32_t
QuicTransportParameters::GetInitialMaxData() const
{
    return m_initial_max_data;
}

void
QuicTransportParameters::SetInitialMaxData(uint32_t initialMaxData)
{
    m_initial_max_data = initialMaxData;
}

uint32_t
QuicTransportParameters::GetInitialMaxStreamData() const
{
    return m_initial_max_stream_data;
}

void
QuicTransportParameters::SetInitialMaxStreamData(uint32_t initialMaxStreamData)
{
    m_initial_max_stream_data = initialMaxStreamData;
}

uint32_t
QuicTransportParameters::GetInitialMaxStreamIdBidi() const
{
    return m_initial_max_stream_id_bidi;
}

void
QuicTransportParameters::SetInitialMaxStreamIdBidi(uint32_t initialMaxStreamIdBidi)
{
    m_initial_max_stream_id_bidi = initialMaxStreamIdBidi;
}

uint32_t
QuicTransportParameters::GetInitialMaxStreamIdUni() const
{
    return m_initial_max_stream_id_uni;
}

void
QuicTransportParameters::SetInitialMaxStreamIdUni(uint32_t initialMaxStreamIdUni)
{
    m_initial_max_stream_id_uni = initialMaxStreamIdUni;
}

uint16_t
QuicTransportParameters::GetMaxPacketSize() const
{
    return m_max_packet_size;
}

void
QuicTransportParameters::SetMaxPacketSize(uint16_t maxPacketSize)
{
    m_max_packet_size = maxPacketSize;
}

uint8_t
QuicTransportParameters::GetOmitConnection() const
{
    return m_omit_connection;
}

void
QuicTransportParameters::SetOmitConnection(uint8_t omitConnection)
{
    m_omit_connection = omitConnection;
}

uint8_t
QuicTransportParameters::GetActiveConnectionIdLimit() const
{
    return m_active_connection_id_limit;
}

void
QuicTransportParameters::SetActiveConnectionIdLimit(uint8_t limit)
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
QuicTransportParameters::GetInitialSourceConnectionId() const
{
    return m_initial_source_connection_id;
}

void
QuicTransportParameters::SetInitialSourceConnectionId(uint64_t cid)
{
    m_initial_source_connection_id = cid;
}

uint64_t
QuicTransportParameters::GetOriginalDestinationConnectionId() const
{
    return m_original_destination_connection_id;
}

void
QuicTransportParameters::SetOriginalDestinationConnectionId(uint64_t cid)
{
    m_original_destination_connection_id = cid;
}

uint32_t
QuicTransportParameters::GetInitialMaxStreamDataBidiRemote() const
{
    return m_initial_max_stream_data_bidi_remote;
}

void
QuicTransportParameters::SetInitialMaxStreamDataBidiRemote(uint32_t val)
{
    m_initial_max_stream_data_bidi_remote = val;
}

uint32_t
QuicTransportParameters::GetInitialMaxStreamDataUni() const
{
    return m_initial_max_stream_data_uni;
}

void
QuicTransportParameters::SetInitialMaxStreamDataUni(uint32_t val)
{
    m_initial_max_stream_data_uni = val;
}

uint16_t
QuicTransportParameters::GetMaxAckDelay() const
{
    return m_max_ack_delay;
}

void
QuicTransportParameters::SetMaxAckDelay(uint16_t val)
{
    m_max_ack_delay = val;
}

uint32_t
QuicTransportParameters::GetMinAckDelay() const
{
    return m_min_ack_delay;
}

void
QuicTransportParameters::SetMinAckDelay(uint32_t val)
{
    m_min_ack_delay = val;
}

} // namespace ns3
