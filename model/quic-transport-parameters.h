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

#ifndef QUICTRANSPORTPARAMETERS_H
#define QUICTRANSPORTPARAMETERS_H

#include "quic-connection-id.h"

#include "ns3/buffer.h"
#include "ns3/header.h"

#include <map>
#include <stdint.h>
#include <vector>

namespace ns3
{

/**
 * @ingroup quic
 * The transport parameters of an endpoint (RFC 9000, Section 18).
 *
 * The parameters go on the wire as a list of (identifier, length, value) entries, with the
 * identifier and the length as variable-length integers. A parameter that has its default value is
 * left out, as real endpoints do. A parameter this class does not know is kept as bytes, which also
 * holds the extensions that are added by identifier: see SetRawParameter().
 *
 * As the module does not carry a TLS handshake yet, the list is preceded by its length as a
 * variable-length integer, so that it can be read from the front of the handshake data.
 *
 * Reading checks every parameter (RFC 9000, Section 7.4 and 18.2): a repeated parameter, a value of
 * the wrong size and a value out of range make IsValid() false, and the connection has to be
 * closed with TRANSPORT_PARAMETER_ERROR. The values that are not given have the default of
 * RFC 9000, which is not always the value a new object holds for sending.
 */
class QuicTransportParameters : public Header
{
  public:
    /** Identifier of original_destination_connection_id (RFC 9000, Section 18.2). */
    static constexpr uint64_t ORIGINAL_DESTINATION_CONNECTION_ID = 0x00;
    /** Identifier of max_idle_timeout. */
    static constexpr uint64_t MAX_IDLE_TIMEOUT = 0x01;
    /** Identifier of stateless_reset_token. */
    static constexpr uint64_t STATELESS_RESET_TOKEN = 0x02;
    /** Identifier of max_udp_payload_size. */
    static constexpr uint64_t MAX_UDP_PAYLOAD_SIZE = 0x03;
    /** Identifier of initial_max_data. */
    static constexpr uint64_t INITIAL_MAX_DATA = 0x04;
    /** Identifier of initial_max_stream_data_bidi_local. */
    static constexpr uint64_t INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05;
    /** Identifier of initial_max_stream_data_bidi_remote. */
    static constexpr uint64_t INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06;
    /** Identifier of initial_max_stream_data_uni. */
    static constexpr uint64_t INITIAL_MAX_STREAM_DATA_UNI = 0x07;
    /** Identifier of initial_max_streams_bidi. */
    static constexpr uint64_t INITIAL_MAX_STREAMS_BIDI = 0x08;
    /** Identifier of initial_max_streams_uni. */
    static constexpr uint64_t INITIAL_MAX_STREAMS_UNI = 0x09;
    /** Identifier of ack_delay_exponent. */
    static constexpr uint64_t ACK_DELAY_EXPONENT = 0x0a;
    /** Identifier of max_ack_delay. */
    static constexpr uint64_t MAX_ACK_DELAY = 0x0b;
    /** Identifier of disable_active_migration. */
    static constexpr uint64_t DISABLE_ACTIVE_MIGRATION = 0x0c;
    /** Identifier of preferred_address. */
    static constexpr uint64_t PREFERRED_ADDRESS = 0x0d;
    /** Identifier of active_connection_id_limit. */
    static constexpr uint64_t ACTIVE_CONNECTION_ID_LIMIT = 0x0e;
    /** Identifier of initial_source_connection_id. */
    static constexpr uint64_t INITIAL_SOURCE_CONNECTION_ID = 0x0f;
    /** Identifier of retry_source_connection_id. */
    static constexpr uint64_t RETRY_SOURCE_CONNECTION_ID = 0x10;
    /** Identifier of min_ack_delay (draft-ietf-quic-ack-frequency). */
    static constexpr uint64_t MIN_ACK_DELAY = 0xff04de1b;
    /** Identifier of version_information (RFC 9368). */
    static constexpr uint64_t VERSION_INFORMATION = 0x11;
    /** Identifier of max_datagram_frame_size (RFC 9221). */
    static constexpr uint64_t MAX_DATAGRAM_FRAME_SIZE = 0x20;
    /** Identifier of grease_quic_bit (RFC 9287). */
    static constexpr uint64_t GREASE_QUIC_BIT = 0x2ab2;
    /** Identifier of reset_stream_at (draft-ietf-quic-reliable-stream-reset). */
    static constexpr uint64_t RESET_STREAM_AT = 0x1d;

    QuicTransportParameters();
    ~QuicTransportParameters() override;

    // Inherited from Header
    static TypeId GetTypeId(void);
    TypeId GetInstanceTypeId(void) const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize(void) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * Print the parameters into an output stream.
     *
     * @param os output stream.
     * @param tc the parameters.
     * @return the stream.
     */
    friend std::ostream& operator<<(std::ostream& os, QuicTransportParameters& tc);

    /**
     * Create the parameters an endpoint announces.
     *
     * @param initial_max_stream_data initial_max_stream_data_bidi_local.
     * @param initial_max_data initial_max_data.
     * @param initial_max_stream_id_bidi initial_max_streams_bidi.
     * @param idleTimeout max_idle_timeout in milliseconds.
     * @param max_udp_payload_size max_udp_payload_size: the largest UDP payload the endpoint reads.
     * @param ack_delay_exponent ack_delay_exponent.
     * @param initial_max_stream_id_uni initial_max_streams_uni.
     * @return the parameters.
     */
    static QuicTransportParameters CreateTransportParameters(uint64_t initial_max_stream_data,
                                                             uint64_t initial_max_data,
                                                             uint64_t initial_max_stream_id_bidi,
                                                             uint64_t idleTimeout,
                                                             uint64_t max_udp_payload_size,
                                                             uint8_t ack_delay_exponent,
                                                             uint64_t initial_max_stream_id_uni);

    /**
     * @return false when the bytes read are not valid parameters: an entry is cut short, a
     * parameter is repeated, a value has the wrong size or is out of range.
     */
    bool IsValid() const
    {
        return m_valid;
    }

    /**
     * Keep a parameter of any identifier, to send it as it is. Extensions use this for the
     * parameters that have no accessor, and GREASE for the parameters nobody knows.
     *
     * @param id the identifier.
     * @param value the bytes of the value.
     */
    void SetRawParameter(uint64_t id, const std::vector<uint8_t>& value);

    /** @return the parameters that this class does not interpret, by identifier. */
    const std::map<uint64_t, std::vector<uint8_t>>& GetRawParameters() const
    {
        return m_raw;
    }

    // Getters and setters

    /** @return ack_delay_exponent. */
    uint8_t GetAckDelayExponent() const;
    /** @param ackDelayExponent ack_delay_exponent. */
    void SetAckDelayExponent(uint8_t ackDelayExponent);

    /** @return max_idle_timeout in milliseconds, 0 when there is none. */
    uint64_t GetIdleTimeout() const;
    /** @param idleTimeout max_idle_timeout in milliseconds. */
    void SetIdleTimeout(uint64_t idleTimeout);

    /** @return initial_max_data. */
    uint64_t GetInitialMaxData() const;
    /** @param initialMaxData initial_max_data. */
    void SetInitialMaxData(uint64_t initialMaxData);

    /** @return initial_max_stream_data_bidi_local. */
    uint64_t GetInitialMaxStreamData() const;
    /** @param initialMaxStreamData initial_max_stream_data_bidi_local. */
    void SetInitialMaxStreamData(uint64_t initialMaxStreamData);

    /** @return initial_max_stream_data_bidi_remote. */
    uint64_t GetInitialMaxStreamDataBidiRemote() const;
    /** @param val initial_max_stream_data_bidi_remote. */
    void SetInitialMaxStreamDataBidiRemote(uint64_t val);

    /** @return initial_max_stream_data_uni. */
    uint64_t GetInitialMaxStreamDataUni() const;
    /** @param val initial_max_stream_data_uni. */
    void SetInitialMaxStreamDataUni(uint64_t val);

    /** @return max_ack_delay in milliseconds. */
    uint64_t GetMaxAckDelay() const;
    /** @param val max_ack_delay in milliseconds. */
    void SetMaxAckDelay(uint64_t val);

    /** @return min_ack_delay in microseconds, 0 when the endpoint does not support ACK_FREQUENCY. */
    /** @return true when the parameters have version_information (RFC 9368). */
    bool HasVersionInformation() const
    {
        return m_has_version_information;
    }

    /** @return the Chosen Version of version_information. */
    uint32_t GetChosenVersion() const
    {
        return m_chosen_version;
    }

    /** @return the Available Versions of version_information, the preferred one first. */
    const std::vector<uint32_t>& GetAvailableVersions() const
    {
        return m_available_versions;
    }

    /**
     * Set version_information.
     *
     * @param chosen the version of the packets that carry it.
     * @param available the versions the endpoint can use, in order of preference.
     */
    void SetVersionInformation(uint32_t chosen, const std::vector<uint32_t>& available)
    {
        m_has_version_information = true;
        m_chosen_version = chosen;
        m_available_versions = available;
    }

    /** @return max_datagram_frame_size (RFC 9221), 0 when the endpoint does not take datagrams. */
    uint64_t GetMaxDatagramFrameSize() const
    {
        return m_max_datagram_frame_size;
    }

    /** @param size max_datagram_frame_size, 0 to leave it out. */
    void SetMaxDatagramFrameSize(uint64_t size)
    {
        m_max_datagram_frame_size = size;
    }

    /** @return true when the endpoint sends the grease_quic_bit parameter (RFC 9287). */
    bool GetGreaseQuicBit() const
    {
        return m_grease_quic_bit;
    }

    /** @param value true to send grease_quic_bit. */
    void SetGreaseQuicBit(bool value)
    {
        m_grease_quic_bit = value;
    }

    /** @return true when the endpoint sends the reset_stream_at parameter. */
    bool GetResetStreamAt() const
    {
        return m_reset_stream_at;
    }

    /** @param value true to send reset_stream_at. */
    void SetResetStreamAt(bool value)
    {
        m_reset_stream_at = value;
    }

    uint64_t GetMinAckDelay() const;
    /** @param val min_ack_delay in microseconds. */
    void SetMinAckDelay(uint64_t val);

    /** @return initial_max_streams_bidi. */
    uint64_t GetInitialMaxStreamIdBidi() const;
    /** @param initialMaxStreamIdBidi initial_max_streams_bidi. */
    void SetInitialMaxStreamIdBidi(uint64_t initialMaxStreamIdBidi);

    /** @return initial_max_streams_uni. */
    uint64_t GetInitialMaxStreamIdUni() const;
    /** @param initialMaxStreamIdUni initial_max_streams_uni. */
    void SetInitialMaxStreamIdUni(uint64_t initialMaxStreamIdUni);

    /** @return max_udp_payload_size: the largest UDP payload the endpoint reads. */
    uint64_t GetMaxUdpPayloadSize() const;
    /** @param maxUdpPayloadSize max_udp_payload_size. */
    void SetMaxUdpPayloadSize(uint64_t maxUdpPayloadSize);

    /** @return the upper 64 bits of stateless_reset_token. */
    uint64_t GetStatelessResetTokenHi() const;
    /** @return the lower 64 bits of stateless_reset_token. */
    uint64_t GetStatelessResetTokenLo() const;
    /**
     * Set stateless_reset_token. A token of zeros is not sent.
     *
     * @param hi the upper 64 bits.
     * @param lo the lower 64 bits.
     */
    void SetStatelessResetToken(uint64_t hi, uint64_t lo);

    /** @return active_connection_id_limit. */
    uint64_t GetActiveConnectionIdLimit() const;
    /** @param limit active_connection_id_limit. */
    void SetActiveConnectionIdLimit(uint64_t limit);

    /** @return 1 when disable_active_migration is present. */
    uint8_t GetDisableActiveMigration() const;
    /** @param disable 1 to send disable_active_migration. */
    void SetDisableActiveMigration(uint8_t disable);

    /** @return initial_source_connection_id. */
    QuicConnectionId GetInitialSourceConnectionId() const;
    /** @param cid initial_source_connection_id. */
    void SetInitialSourceConnectionId(const QuicConnectionId& cid);

    /** @return original_destination_connection_id, empty when it is absent. */
    QuicConnectionId GetOriginalDestinationConnectionId() const;
    /** @param cid original_destination_connection_id, sent by a server. */
    void SetOriginalDestinationConnectionId(const QuicConnectionId& cid);

    /** @return retry_source_connection_id, empty when it is absent. */
    QuicConnectionId GetRetrySourceConnectionId() const;
    /** @param cid retry_source_connection_id, sent by a server that sent a Retry packet. */
    void SetRetrySourceConnectionId(const QuicConnectionId& cid);

    /**
     * @param lhs parameters.
     * @param rhs other parameters.
     * @return true when every parameter is equal.
     */
    friend bool operator==(const QuicTransportParameters& lhs, const QuicTransportParameters& rhs);

  private:
    /**
     * Write the entries of the list, which GetSerializedSize() and Serialize() send behind their
     * length.
     *
     * @return the bytes.
     */
    std::vector<uint8_t> EncodeEntries() const;

    /** Give every parameter the default of RFC 9000, Section 18.2: what an absent one means. */
    void ResetToDefaults();

    uint64_t m_initial_max_stream_data{0};    //!< initial_max_stream_data_bidi_local
    uint64_t m_initial_max_data{0};           //!< initial_max_data
    uint64_t m_initial_max_stream_id_bidi{0}; //!< initial_max_streams_bidi
    uint64_t m_idleTimeout{300000};           //!< max_idle_timeout in milliseconds, 0 = disabled
    uint64_t m_max_udp_payload_size{65527};   //!< max_udp_payload_size
    uint64_t m_stateless_reset_token_hi{0};   //!< upper 64 bits of stateless_reset_token
    uint64_t m_stateless_reset_token_lo{0};   //!< lower 64 bits of stateless_reset_token
    uint8_t m_ack_delay_exponent{3};          //!< ack_delay_exponent
    uint64_t m_initial_max_stream_id_uni{0};  //!< initial_max_streams_uni
    uint64_t m_initial_max_stream_data_bidi_remote{0}; //!< initial_max_stream_data_bidi_remote
    uint64_t m_initial_max_stream_data_uni{0};         //!< initial_max_stream_data_uni
    bool m_has_version_information{false};             //!< version_information is present
    uint32_t m_chosen_version{0};                      //!< its Chosen Version
    std::vector<uint32_t> m_available_versions;        //!< its Available Versions
    uint64_t m_max_datagram_frame_size{0};             //!< max_datagram_frame_size
    bool m_grease_quic_bit{false};                     //!< grease_quic_bit is present
    bool m_reset_stream_at{false};                     //!< reset_stream_at is present
    uint64_t m_min_ack_delay{0};                       //!< min_ack_delay in microseconds
    uint64_t m_max_ack_delay{25};                      //!< max_ack_delay in milliseconds
    uint64_t m_active_connection_id_limit{2};          //!< active_connection_id_limit
    uint8_t m_disable_active_migration{0};             //!< disable_active_migration
    QuicConnectionId m_initial_source_connection_id;   //!< initial_source_connection_id
    QuicConnectionId m_original_destination_connection_id; //!< original_destination_connection_id
    QuicConnectionId m_retry_source_connection_id;         //!< retry_source_connection_id
    std::map<uint64_t, std::vector<uint8_t>> m_raw; //!< parameters that have no accessor
    bool m_valid{true};                             //!< the bytes read were valid parameters
};

} // namespace ns3

#endif /* QUICTRANSPORTPARAMETERS_H */
