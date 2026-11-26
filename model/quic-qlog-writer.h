/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_QLOG_WRITER_H
#define QUIC_QLOG_WRITER_H

#include "quic-connection-id.h"
#include "quic-header.h"
#include "quic-transport-parameters.h"

#include "ns3/address.h"
#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/packet.h"

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace ns3
{

/**
 * @ingroup quic
 *
 * Writes the events of one QUIC connection to a qlog file, as defined by
 * draft-ietf-quic-qlog-main-schema-15 (the JSON text sequence serialization, extension .sqlog)
 * and draft-ietf-quic-qlog-quic-events-14.
 *
 * Every record is an RS byte (0x1E), a JSON text and an LF. The first record is the file header,
 * the following ones are the events. The file is created when the first event is written, in the
 * directory given to Configure(), and is named after the node, the vantage point and the group id
 * (the Destination Connection ID of the first Initial packet, as the draft suggests).
 *
 * Packets are logged with the bytes the simulator has: the headers and the frames are exact, the
 * AEAD tag is counted in the lengths but is not part of the data. Times are in milliseconds from
 * the start of the simulation.
 */
class QuicQlogWriter : public Object
{
  public:
    /**
     * Get the type ID.
     *
     * @return the object TypeId.
     */
    static TypeId GetTypeId();

    QuicQlogWriter();
    ~QuicQlogWriter() override;

    /**
     * Say where the file goes and who writes it.
     *
     * @param directory the directory of the file, created when it does not exist.
     * @param vantage "client" or "server".
     * @param nodeId the id of the node of the connection.
     */
    void Configure(const std::string& directory, const std::string& vantage, uint32_t nodeId);

    /**
     * Set the group id of the trace, the Original Destination Connection ID of the connection. It
     * has to be set before the first event.
     *
     * @param odcid the id.
     */
    void SetGroupId(const QuicConnectionId& odcid);

    /** @return true when the group id was set. */
    bool HasGroupId() const;

    /** @return the name of the file, empty until the first event is written. */
    std::string GetFileName() const;

    /** Flush and close the file. Later events open it again, without a second header. */
    void Close();

    /**
     * Log quic:connection_started.
     *
     * @param local the local address and port.
     * @param remote the address and port of the peer.
     * @param localCid the connection ids the local end listens on.
     */
    void ConnectionStarted(const Address& local,
                           const Address& remote,
                           const QuicConnectionId& localCid);

    /**
     * Log quic:connection_closed.
     *
     * @param initiator "local" or "remote".
     * @param trigger the draft's trigger: idle_timeout, application, error, version_mismatch,
     *                stateless_reset, aborted or unspecified.
     * @param errorCode the error code, when the trigger is error or application.
     * @param hasErrorCode true when errorCode is meaningful.
     * @param applicationError true when the code is an application protocol code.
     * @param reason a phrase for the closing, may be empty.
     */
    void ConnectionClosed(const std::string& initiator,
                          const std::string& trigger,
                          uint64_t errorCode,
                          bool hasErrorCode,
                          bool applicationError,
                          const std::string& reason);

    /**
     * Log quic:parameters_set.
     *
     * @param initiator "local" or "remote".
     * @param tp the transport parameters.
     */
    void ParametersSet(const std::string& initiator, const QuicTransportParameters& tp);

    /**
     * Log quic:version_information.
     *
     * @param chosen the version of the connection.
     * @param local the versions this end supports.
     * @param isClient true when this end is the client.
     */
    void VersionInformation(uint32_t chosen, const std::vector<uint32_t>& local, bool isClient);

    /**
     * Log quic:packet_sent.
     *
     * @param header the header of the packet.
     * @param payload the frames of the packet.
     * @param ackDelayExponent the ack_delay_exponent that scales the ACK delay of the frames.
     * @param mtuProbe true for a packet sent only to probe the path MTU.
     */
    void PacketSent(const QuicHeader& header,
                    Ptr<const Packet> payload,
                    uint8_t ackDelayExponent,
                    bool mtuProbe);

    /**
     * Log quic:packet_received.
     *
     * @param header the header of the packet.
     * @param payload the frames of the packet.
     * @param ackDelayExponent the ack_delay_exponent that scales the ACK delay of the frames.
     */
    void PacketReceived(const QuicHeader& header,
                        Ptr<const Packet> payload,
                        uint8_t ackDelayExponent);

    /**
     * Log quic:packet_dropped.
     *
     * @param header the header of the packet, nullptr when it could not be read.
     * @param size the number of bytes of the packet.
     * @param trigger the draft's trigger: internal_error, rejected, unsupported, invalid,
     *                duplicate, connection_unknown, decryption_failure, keys_unavailable or
     *                general.
     * @param detail a description of the cause, may be empty.
     */
    void PacketDropped(const QuicHeader* header,
                       uint32_t size,
                       const std::string& trigger,
                       const std::string& detail);

    /**
     * Log quic:packet_lost.
     *
     * @param packetNumber the packet number.
     * @param trigger reordering_threshold, time_threshold or pto_expired.
     */
    void PacketLost(uint64_t packetNumber, const std::string& trigger);

    /**
     * Log quic:udp_datagrams_sent or quic:udp_datagrams_received.
     *
     * @param sent true for a sent datagram.
     * @param size the size of the UDP payload.
     */
    void UdpDatagram(bool sent, uint32_t size);

    /**
     * Log quic:recovery_metrics_updated. Only the values that changed since the last call are
     * written, and nothing when none did.
     *
     * @param minRtt the minimum RTT, Time::Max() while there is no sample.
     * @param smoothedRtt the smoothed RTT.
     * @param latestRtt the latest RTT sample.
     * @param rttVar the RTT variance.
     * @param ptoCount the number of probe timeouts since the last acknowledgment.
     * @param cwnd the congestion window in bytes.
     * @param bytesInFlight the bytes in flight.
     * @param ssthresh the slow start threshold in bytes.
     */
    void RecoveryMetrics(Time minRtt,
                         Time smoothedRtt,
                         Time latestRtt,
                         Time rttVar,
                         uint32_t ptoCount,
                         uint32_t cwnd,
                         uint32_t bytesInFlight,
                         uint32_t ssthresh);

    /**
     * Log quic:congestion_state_updated.
     *
     * @param oldState the previous state.
     * @param newState the new state.
     * @param trigger why it changed, may be empty.
     */
    void CongestionStateUpdated(const std::string& oldState,
                                const std::string& newState,
                                const std::string& trigger);

    /**
     * Log quic:timer_updated.
     *
     * @param timerType "ack", "pto", "loss_timeout", "idle_timeout" or "handshake_timeout".
     * @param event "set", "expired" or "cancelled".
     * @param delta the time until the timer fires, for "set".
     */
    void TimerUpdated(const std::string& timerType, const std::string& event, Time delta);

    /**
     * Describe the frames of a packet payload as the elements of a JSON array.
     *
     * @param payload the frames.
     * @param ackDelayExponent the ack_delay_exponent that scales the ACK delay of the frames.
     * @return the JSON text, "[...]".
     */
    static std::string FramesToJson(Ptr<const Packet> payload, uint8_t ackDelayExponent);

    /**
     * Describe a packet header as a JSON object, the PacketHeader of the draft.
     *
     * @param header the header.
     * @return the JSON text, "{...}".
     */
    static std::string HeaderToJson(const QuicHeader& header);

    /**
     * Format a duration in milliseconds, with six decimals.
     *
     * @param t the duration.
     * @return the text, such as "12.345678".
     */
    static std::string FormatMs(Time t);

    /**
     * Escape and quote a text for JSON.
     *
     * @param text the text.
     * @return the quoted text.
     */
    static std::string Quote(const std::string& text);

    /**
     * Write bytes as a lowercase hexadecimal string, without quotes.
     *
     * @param bytes the bytes.
     * @param count the number of bytes.
     * @return the text.
     */
    static std::string Hex(const uint8_t* bytes, size_t count);

  private:
    /**
     * Write one event record, opening the file first when needed.
     *
     * @param name the event name, such as "quic:packet_sent".
     * @param data the JSON object that is the data of the event.
     */
    void Event(const std::string& name, const std::string& data);

    /** Open the file and write the header record. */
    void Open();

    /**
     * Describe a packet for the events that carry a header and the raw lengths.
     *
     * @param header the header.
     * @param payloadSize the bytes of the frames.
     * @return the members "header" and "raw", as JSON text without braces.
     */
    static std::string PacketMembers(const QuicHeader& header, uint32_t payloadSize);

    std::string m_directory;                     //!< where the file goes
    std::string m_vantage;                       //!< "client" or "server"
    uint32_t m_nodeId{0};                        //!< node of the connection
    QuicConnectionId m_groupId;                  //!< Original Destination Connection ID
    bool m_hasGroupId{false};                    //!< true when m_groupId was set
    std::string m_fileName;                      //!< path of the file, empty until opened
    std::ofstream m_out;                         //!< the file
    bool m_headerWritten{false};                 //!< true after the header record
    std::map<uint64_t, std::string> m_sentTypes; //!< packet type of the latest sent packets

    bool m_metricsValid{false}; //!< true once metrics were logged
    int64_t m_lastMinRtt{0};    //!< last minimum RTT logged, in ns
    int64_t m_lastSrtt{0};      //!< last smoothed RTT logged, in ns
    int64_t m_lastLatestRtt{0}; //!< last RTT sample logged, in ns
    int64_t m_lastRttVar{0};    //!< last RTT variance logged, in ns
    uint32_t m_lastPto{0};      //!< last PTO count logged
    uint32_t m_lastCwnd{0};     //!< last congestion window logged
    uint32_t m_lastInFlight{0}; //!< last bytes in flight logged
    uint32_t m_lastSsthresh{0}; //!< last slow start threshold logged
};

} // namespace ns3

#endif // QUIC_QLOG_WRITER_H
