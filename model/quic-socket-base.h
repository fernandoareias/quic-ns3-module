/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#ifndef QUICSOCKETBASE_H
#define QUICSOCKETBASE_H

#include "quic-header.h"
#include "quic-socket-rx-buffer.h"
#include "quic-socket-tx-buffer.h"
#include "quic-socket.h"
#include "quic-subheader.h"
#include "quic-transport-parameters.h"

#include "ns3/event-id.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/timer.h"
#include "ns3/traced-value.h"

#include <set>
// #include "ns3/ipv4-end-point.h"
#include "quic-socket-tx-scheduler.h"
#include "quic-socket-tx-streamfifo-scheduler.h"

#include "ns3/tcp-congestion-ops.h"
#include "ns3/tcp-socket-base.h"

#include <map>

namespace ns3
{

class QuicL5Protocol;
class QuicL4Protocol;

/**
 * \brief RFC 9002 §2 Packet Number Space identifier.
 *
 * QUIC maintains separate packet number spaces for Initial, Handshake, and
 * Application Data (1-RTT / 0-RTT) packets.  Loss detection, ACK tracking,
 * and timer state are maintained independently per space.
 */
enum PacketNumberSpace : uint8_t
{
    INITIAL_SPACE = 0,   //!< Initial packet number space
    HANDSHAKE_SPACE = 1, //!< Handshake packet number space
    APP_DATA_SPACE = 2,  //!< Application-data (1-RTT) packet number space
    NUM_SPACES = 3       //!< Sentinel — number of spaces
};

/**
 * \brief Data structure that records the congestion state of a connection
 *
 * In this data structure, basic informations that should be passed between
 * socket and the congestion control algorithm are saved.
 */
class QuicSocketState : public TcpSocketState
{
  public:
    /**
     * Get the type ID.
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    QuicSocketState();
    QuicSocketState(const QuicSocketState& other);

    virtual ~QuicSocketState(void)
    {
    }

    // Loss Detection variables of interest
    EventId m_lossDetectionAlarm; //!< Multi-modal alarm used for loss detection.
    uint32_t m_handshakeCount;    /**< The number of times the handshake packets have been
                                   * retransmitted without receiving an ack. */
    uint32_t m_tlpCount;          /**< The number of times a tail loss probe has been sent without
                                   *   receiving an ack. */
    uint32_t m_rtoCount; //!< The number of times an rto has been sent without receiving an ack.
    SequenceNumber32 m_largestSentBeforeRto; //!< The last packet number sent prior to the first
                                             //!< retransmission timeout.
    Time m_timeOfLastSentPacket;             //!< The time the most recent packet was sent.
    SequenceNumber32
        m_largestAckedPacket; //!< The largest packet number acknowledged in an ACK frame.
    bool m_lostSpanHasAck{
        false}; //!< An acknowledged packet was sent between the lost ones (RFC 9002 s7.6.2)
    // RFC 9002 §2: per-space largest-acked tracking.
    // Index = PacketNumberSpace (INITIAL_SPACE=0, HANDSHAKE_SPACE=1, APP_DATA_SPACE=2).
    SequenceNumber32 m_largestAckedPacketSpace[NUM_SPACES]; //!< Per-space largest acked

    Time m_latestRtt;   /**< The most recent RTT measurement made when receiving an ack for a
                         *   previously unacked packet. */
    Time m_smoothedRtt; //!< The smoothed RTT of the connection, computed as described in [RFC6298].
    Time m_rttVar;      //!< The RTT variance, computed as described in [RFC6298].
    Time m_minRtt; //!< The minimum RTT seen in the connection, ignoring ack delay (Time::Max ()
                   //!< until the first sample).
    Time m_maxAckDelay; /**< The peer's max_ack_delay transport parameter (RFC 9000 s18.2, default
                         * 25 ms). Used to bound the ack delay subtracted from RTT samples (RFC 9002
                         * s5.3) and as the ack-delay term of the PTO (RFC 9002 s6.2.1). */
    Time m_timeOfLastAckElicitingSent; //!< Send time of the latest ack-eliciting packet; the PTO is
                                       //!< measured from it (RFC 9002 s6.2.1).
    Time m_lossTime; /**< The time at which the next packet will be considered lost based
                      *   on early transmit or exceeding the reordering window in time. */
    // RFC 9002 §6.1.2: per-space loss time (earliest time-based loss deadline per space).
    Time m_lossTimeSpace[NUM_SPACES]; //!< Per-space loss time

    // Congestion Control constants of interests
    uint32_t m_kMinimumWindow;     //!< Default minimum congestion window.
    double m_kLossReductionFactor; //!< Reduction in congestion window when a new loss event is
                                   //!< detected.
    uint32_t m_kPersistentCongestionThreshold; /**< RFC 9002 §7.6.3: multiplier for persistent
                                                * congestion duration. RECOMMENDED = 3. */
    bool m_kPersistentCongestionByPto{true};   //!< msquic: persistent congestion when more than 2
                                               //!< consecutive PTOs preceded the loss
    uint32_t m_ptoCountForLoss{
        0}; //!< Consecutive PTOs before the ACK/timer being processed (msquic ProbeCount)

    // Congestion Control variables of interests
    SequenceNumber32
        m_endOfRecovery; /**< The largest packet number sent when QUIC detects a loss. When a larger
                          * packet is acknowledged, QUIC exits recovery. */

    // Loss Detection constants of interest
    uint32_t m_kMaxTLPs;     //!< Maximum number of tail loss probes before an RTO fires.
    uint32_t m_kMaxPtoCount; /**< RFC 9002 §6.2.1: max consecutive PTOs without any new ACK before
                              *   abandoning the connection. SHOULD = 8 (analogous to TCP
                              * MaxRetxThreshold). */
    uint32_t m_kReorderingThreshold; /**< Maximum reordering in packet number space before FACK
                                      * style loss detection considers a packet lost. */
    double
        m_kTimeReorderingFraction;  /**< Maximum reordering in time space before time based loss
                                     * detection considers a packet lost. In fraction of an RTT. */
    bool m_kUsingTimeLossDetection; /**< Whether time based loss detection is in use. If false, uses
                                     * FACK style loss detection. */
    Time m_kMinTLPTimeout; //!< Minimum time in the future a tail loss probe alarm may be set for.
    Time m_kMinRTOTimeout; //!< Minimum time in the future an RTO alarm may be set for.
    Time m_kDelayedAckTimeout; //!< The lenght of the peer's delayed ack timer.
    uint8_t m_alarmType;       //!< The type of the next alarm
    Time m_nextAlarmTrigger;   //<! Time of the next alarm
    Time m_kDefaultInitialRtt; //!< The default RTT used before an RTT sample is taken.
    uint32_t m_kMaxPacketsReceivedBeforeAckSend; //!< The number of packets to be received before an
                                                 //!< ACK is triggered

    // RateSample variables of interest
    uint64_t m_delivered{0};          //!< The total amount of data in bytes delivered so far
    Time m_deliveredTime{Seconds(0)}; //!< Simulation time when m_delivered was last updated
    Time m_firstSentTime{
        Seconds(0)}; //!< The send time of the packet that was most recently marked as delivered
    uint64_t m_appLimitedUntil{
        0}; //!< Connection is application-limited until m_appLimitedUntil > m_delivered
    uint32_t m_txItemDelivered{0};      /**< amount of data (in bytes) delivered when last packet
                                            marked asdelivered was first sent */
    uint32_t m_lastAckedSackedBytes{0}; //!< Size of data sacked in the last ack
    uint32_t m_ackBytesSent{0};         //!< amount of ACK-only bytes sent

    // RFC 9002 conformance flags
    bool m_handshakeConfirmed{false}; /**< RFC 9002 §5.3: true after handshake is confirmed;
                                       *   max_ack_delay MUST be ignored until this is true. */
    // RFC 9002 §9.2 / RFC 9000 §19.3.2: ECN-CE count last reported by the peer
    uint64_t m_peerEcnCeCount{0}; /**< RFC 9002 §9.2: tracks the last-seen ECN-CE count from
                                   *   peer ACK_ECN frames; an increment triggers congestion. */
};

/**
 * \ingroup quic
 * \brief Set of received packet numbers kept as ranges (msquic: QUIC_RANGE), so membership tests
 * and ACK frame construction do not depend on the number of packets received.
 */
class QuicPnRanges
{
  public:
    /** \return true if no packet number was recorded */
    bool Empty(void) const
    {
        return m_ranges.empty();
    }

    /** \return the largest recorded packet number; the set must not be empty */
    uint32_t Largest(void) const
    {
        return m_ranges.rbegin()->second;
    }

    /**
     * \param pn a packet number
     * \return true if pn was recorded
     */
    bool Contains(uint32_t pn) const
    {
        auto it = m_ranges.upper_bound(pn);
        if (it == m_ranges.begin())
        {
            return false;
        }
        --it;
        return pn <= it->second;
    }

    /** \brief Record a packet number, merging adjacent ranges */
    void Add(uint32_t pn)
    {
        auto next = m_ranges.upper_bound(pn);
        uint32_t lo = pn;
        uint32_t hi = pn;
        if (next != m_ranges.begin())
        {
            auto prev = std::prev(next);
            if (pn <= prev->second)
            {
                return;
            }
            if (prev->second + 1 == pn)
            {
                lo = prev->first;
                m_ranges.erase(prev);
            }
        }
        if (next != m_ranges.end() && next->first == pn + 1)
        {
            hi = next->second;
            m_ranges.erase(next);
        }
        m_ranges[lo] = hi;
        while (m_ranges.size() > kMaxRanges)
        {
            m_ranges.erase(m_ranges.begin());
        }
    }

    /** \return how many recorded packet numbers lie in (low, high] */
    uint32_t CountAbove(uint32_t low, uint32_t high) const
    {
        uint32_t n = 0;
        for (auto it = m_ranges.rbegin(); it != m_ranges.rend(); ++it)
        {
            if (it->second <= low)
            {
                break;
            }
            uint32_t lo = std::max(it->first, low + 1);
            uint32_t hi = std::min(it->second, high);
            if (hi >= lo)
            {
                n += hi - lo + 1;
            }
        }
        return n;
    }

    /** \brief The ranges, lowest first, as (first, last) */
    const std::map<uint32_t, uint32_t>& Ranges(void) const
    {
        return m_ranges;
    }

  private:
    static constexpr size_t kMaxRanges = 2048; //!< QUIC_MAX_RANGE_ACK_PACKETS
    std::map<uint32_t, uint32_t> m_ranges;
};

/**
 * \ingroup socket
 * \ingroup quic
 *
 * \brief A base class for implementation a QUIC socket.
 *
 * This class mimics the TcpSocketBase class implementation (and documentation).
 * It contains the essential components of QUIC, as well as a sockets
 * interface for upper layers to call. This class provides capabilities to
 * set up a connection, possibly with multiple streams, and manages the life cycle of
 * the connection. As for the TCP implementation, congestion control
 * is delegated to subclasses of QuicCongestionOps. In order to mimic the
 * TcpSocketBase implementation and avoid repeating code, the implementation is
 * not perfectly compliant with the QUIC Internet Draft; e.g., sequence numbers
 * are 32 bits long instead of 64. Deviations from the standard are commented
 *
 * Congestion control interface
 * ---------------------------
 *
 * Congestion control, as in the TCP implementation, has been split from
 * QuicSocketBase. The goal is to provide compatibility with the TCP congestion
 * control implementations, as well as the possibility of extending it with
 * new QUIC-related capabilities
 *
 * Transmission Control Block (TCB)
 * --------------------------------
 *
 * Taking as a reference the TCP implementation, the variables needed to congestion
 * control classes to operate correctly have been moved inside the QuicSocketState
 * class. Extending TcpSocketState, the class contains information on both the Quic
 * and the TCP windows and thresholds as well as the Congestion state machine of TCP.
 *
 * Streams
 * --------------------------------
 *
 * Streams in QUIC constitute a lightweight, ordered byte-stream abstraction within a
 * QUIC connection. The multiplexing/demultiplexing of frames in streams is handled
 * through L5 Protocol that plays a dispatcher role. Frames are buffered in reception
 * and in transmission and are processed in QuicStreams according to QUIC semantics.
 *
 */
class QuicSocketBase : public QuicSocket
{
  public:
    static const uint16_t MIN_INITIAL_PACKET_SIZE;

    /**
     * Get the type ID.
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    /**
     * \brief Build an object. InitializeScheduling() must be called after construction to
     * instantiate the frame scheduler, or the construction will fail
     *
     */
    QuicSocketBase(void);
    QuicSocketBase(const QuicSocketBase&);

    virtual ~QuicSocketBase(void);

    /**
     * \brief Notify the application that a new connection has been created.
     * Public wrapper for the protected Socket::NotifyNewConnectionCreated().
     * \param socket the new socket created for the connection
     * \param from the address of the remote peer
     */
    void NotifyNewConnection(Ptr<Socket> socket, const Address& from);

    /**
     * \brief Install a congestion control algorithm on this socket
     *
     * \param algo Algorithm to be installed
     */
    void SetCongestionControlAlgorithm(Ptr<TcpCongestionOps> algo);

    /**
     * \brief Common part of the two Bind(), i.e. set callback to receive data
     *
     * \returns 0 on success, -1 on failure
     */
    int SetupCallback(void);

    /**
     * \brief Send the initial handshake command to the other endpoint
     *
     * This method sends packets to initiate different handshakes,
     * according to the type parameters
     *
     * \param type the type of handshake (from QuicHeader)
     * \param quicHeader the QUIC header to be used
     * \param packet a packet
     */
    void SendInitialHandshake(uint8_t type, const QuicHeader& quicHeader, Ptr<Packet> packet);

    /**
     * \brief Called by QuicL5Protocol to forward to the socket a control frame.
     * In this implementation, only ACK, CONNECTION_CLOSE and CONNECTION_CLOSE_APP
     * are supported.
     *
     * \param sub the QuicSubheader of the control frame
     */
    void OnReceivedFrame(QuicSubheader& sub);

    /**
     * \brief Called when an ACK frame is received
     *
     * \param sub the QuicSubheader of the ACK frame
     */
    void OnReceivedAckFrame(QuicSubheader& sub);

    /**
     * \brief Called on sending an ACK frame
     *
     * \return the generated ACK frame
     */
    Ptr<Packet> OnSendingAckFrame();

    /**
     * \brief Return an object with the transport parameters of this socket
     *
     * \return the transport parameters of the socket
     */
    QuicTransportParameters OnSendingTransportParameters();

    /**
     * \brief Called when Quic transport parameters are received
     *
     * \param transportParameters the received transport parameters
     */
    void OnReceivedTransportParameters(QuicTransportParameters transportParameters);

    /**
     * Take the limits on what this endpoint sends from the transport parameters of the peer
     * \param transportParameters the parameters the peer announced, or those remembered from an
     * earlier connection
     */
    void ApplyPeerLimits(const QuicTransportParameters& transportParameters);

    /** Send the writes the application made before the connection could carry them */
    void FlushPendingWrites();

    /**
     * \brief Add a stream frame to the TX buffer and call SendPendingData
     *
     * \param frame a smart pointer to a packet
     * \return the size of the frame
     */
    int AppendingTx(Ptr<Packet> frame);

    /**
     * \brief Add a stream frame to the RX buffer and call NotifyDataRecv
     *
     * \param frame a smart pointer to a packet
     * \param the RX address
     * \return the size of the frame added, 0 if the buffer is full
     */
    int AppendingRx(Ptr<Packet> frame, Address& address);

    /**
     * \brief Set the L4 Protocol
     *
     * \param quic the L4 Protocol to be set
     */
    void SetQuicL4(Ptr<QuicL4Protocol> quic);

    /**
     * \brief Initialize socket TX buffer scheduler
     */
    void InitializeScheduling();

    /**
     * \brief Set the connection ID, e.g., for client-initiated connections
     *
     * \param connectionId the connection ID
     */
    void SetConnectionId(const QuicConnectionId& connectionId);

    /**
     * \brief Get the connection ID
     *
     * \return the connection ID
     */
    QuicConnectionId GetConnectionId(void) const;

    /**
     * \brief Set the Quic protocol version
     *
     * \param version the Quic protocol version
     */
    void SetVersion(uint32_t version);

    /**
     * \brief Get the available window
     *
     * \return the available window
     */
    uint32_t AvailableWindow() const;

    /**
     * \brief Get the connection window
     *
     * \return the connection window
     */
    uint32_t ConnectionWindow() const;

    /**
     * \brief Return total bytes in flight
     *
     * \returns total bytes in flight
     */
    uint32_t BytesInFlight() const;

    /**
     * \brief Get the maximum amount of data that can be sent on the connection
     *
     * \return the maximum amount of data that can be sent on the connection
     */
    uint64_t GetConnectionMaxData() const;

    /**
     * \brief Set the maximum amount of data that can be sent on the connection
     *
     * \param maxData the maximum amount of data that can be sent on the connection
     */
    void SetConnectionMaxData(uint64_t maxData);

    /**
     * \brief Own initial per-stream receive window (advertised to the peer)
     * \return the window in bytes
     */
    uint32_t GetOwnInitialMaxStreamData() const;

    /**
     * \brief Whether Close() was called and buffered data is still being flushed
     * \return true while flushing
     */
    bool IsFlushingOnClose() const;

    /**
     * \brief Own connection-level receive window (advertised to the peer)
     * \return the window in bytes
     */
    uint32_t GetConnRecvWindow() const;

    /**
     * \brief Smoothed RTT estimate
     * \return the smoothed RTT
     */
    Time GetSmoothedRtt() const;

    /**
     * \brief Get the maximum amount of data per stream
     *
     * 0 means unlimited
     *
     * \return the maximum amount of data per stream
     */
    uint32_t GetInitialMaxStreamData() const;

    /**
     * \brief Get the state in the Congestion state machine
     *
     * \return the state in the Congestion state machine
     */
    QuicSocket::QuicStates_t GetSocketState() const;

    /**
     * \brief abort the connection due to an error
     *
     * \param transportErrorCode the error code
     * \param a sentence explaining the error
     * \param applicationClose a bool that signals that the application trigger the abortion
     */
    void AbortConnection(uint16_t transportErrorCode,
                         const char* reasonPhrase,
                         bool applicationClose = false);

    /**
     * \brief Send a STREAMS_BLOCKED frame (RFC 9000 §19.14)
     * \param streamLimit the current stream limit
     * \param bidirectional true for bidi streams, false for uni
     */
    void SendStreamsBlockedFrame(uint64_t streamLimit, bool bidirectional);

    /**
     * \brief Check if transport parameters are ever being received
     *
     * \return true if received, false otherwise
     */
    bool GetReceivedTransportParametersFlag() const;

    /**
     * \brief check if the data received in this connection exceeds MAX_DATA
     *
     * \param a vector of pairs with received frames and subheaders
     * \return a boolean, true if the limit was exceeded
     */
    bool CheckIfPacketOverflowMaxDataLimit(
        std::vector<std::pair<Ptr<Packet>, QuicSubheader>> disgregated);

    /**
     * \brief Get the maximum of stream ID (i.e., number of streams - 1)
     *
     * Consider the maximum between the unidirectional and bidirectional
     * stream IDs
     *
     * \return the maximum stream ID
     */
    uint32_t GetMaxStreamId() const;

    /**
     * \brief return true if the packet that has just been received contains transport params
     *
     * \return a boolean, true if the packet that has just been received contains transport params
     */
    bool CouldContainTransportParameters() const;

    /**
     * \brief Get the maximum of stream ID for bidirectional streams (i.e., number of streams - 1)
     *
     * Consider bidirectional stream IDs
     *
     * \return the maximum bidirectional stream ID
     */
    uint32_t GetMaxStreamIdBidirectional() const;

    /**
     * \brief Get the maximum of stream ID for unidirectional streams (i.e., number of streams - 1)
     *
     * Consider unidirectional stream IDs
     *
     * \return the maximum unidirectional stream ID
     */
    uint32_t GetMaxStreamIdUnidirectional() const;

    /**
     * \brief Set the socket TX buffer size.
     *
     * \param size the buffer size (in bytes)
     */
    void SetSocketSndBufSize(uint32_t size);

    /**
     * \brief Get the socket TX buffer size.
     é
     * \returns the buffer size (in bytes)
     */
    uint32_t GetSocketSndBufSize(void) const;

    /**
     * \brief Set the socket RX buffer size.
     *
     * \param size the buffer size (in bytes)
     */
    void SetSocketRcvBufSize(uint32_t size);

    /**
     * \brief Get the socket RX buffer size.
     *
     * \returns the buffer size (in bytes)
     */
    uint32_t GetSocketRcvBufSize(void) const;

    /**
     * \brief Schedule a queue ACK has if needed
     */
    void MaybeQueueAck();

    /**
     * \brief Callback function to hook to QuicSocketState congestion window
     *
     * \param oldValue old cWnd value
     * \param newValue new cWnd value
     */
    void UpdateCwnd(uint32_t oldValue, uint32_t newValue);

    /**
     * \brief Callback function to hook to QuicSocketState slow start threshold
     *
     * \param oldValue old ssTh value
     * \param newValue new ssTh value
     */
    void UpdateSsThresh(uint32_t oldValue, uint32_t newValue);

    /**
     * \brief Callback function to hook to QuicSocketState congestion state
     *
     * \param oldValue old congestion state value
     * \param newValue new congestion state value
     */
    void UpdateCongState(TcpSocketState::TcpCongState_t oldValue,
                         TcpSocketState::TcpCongState_t newValue);

    /**
     * \brief Callback function to hook to QuicSocketState high tx mark
     *
     * \param oldValue old high tx mark
     * \param newValue new high tx mark
     */
    void UpdateHighTxMark(SequenceNumber32 oldValue, SequenceNumber32 newValue);

    /**
     * \brief Callback function to hook to QuicSocketState next tx sequence
     *
     * \param oldValue old nextTxSeq value
     * \param newValue new nextTxSeq value
     */
    void UpdateNextTxSequence(SequenceNumber32 oldValue, SequenceNumber32 newValue);

    /**
     * \brief Set the initial Slow Start Threshold.
     *
     * \param threshold the Slow Start Threshold (in bytes)
     */
    void SetInitialSSThresh(uint32_t threshold);

    /**
     * \brief Get the initial Slow Start Threshold.
     *
     * \returns the Slow Start Threshold (in bytes)
     */
    uint32_t GetInitialSSThresh(void) const;

    /**
     * \brief Set the size of initial packet of the handshake
     * It must be at least 1200 bytes
     *
     * \param the size in bytes
     */
    void SetInitialPacketSize(uint32_t size);

    /**
     * \brief Get the size of initial packet of the handshake
     *
     * \returns the size (in bytes)
     */
    uint32_t GetInitialPacketSize(void) const;

    // Implementation of ns3::Socket virtuals

    /**
     * Send a packet on a stream
     *
     * \param p a smart pointer for the packet
     * \param flags the streamId
     */
    virtual int Send(Ptr<Packet> p, uint32_t flags);
    /**
     * Send a packet without specifying the stream
     * Load balancing of the different streams will be applied
     *
     * \param p a smart pointer for the packet
     */
    virtual int Send(Ptr<Packet> p);
    virtual int SendTo(Ptr<Packet> p, uint32_t flags, const Address& toAddress);
    virtual Ptr<Packet> Recv(uint32_t maxSize, uint32_t flags);
    virtual Ptr<Packet> RecvFrom(uint32_t maxSize, uint32_t flags, Address& fromAddress);
    virtual int Bind(void); // Bind a socket by setting up the UDP socket in QuicL4Protocol
    virtual int Bind(const Address& address);
    virtual int Bind6(void);
    virtual void BindToNetDevice(Ptr<NetDevice> netdevice);
    virtual void SetSegSize(uint32_t size);
    virtual uint32_t GetSegSize(void) const;
    virtual int Listen(void);
    virtual int Connect(const Address& address); // Setup endpoint and create the QUIC L5 protocol
    virtual int Close(void);
    virtual int ShutdownSend(void);

    /**
     * \brief Abruptly terminate the sending side of a stream (RESET_STREAM, RFC 9000 s19.4)
     * \param streamId the stream
     * \param errorCode application error code
     * \return true if the reset was issued
     */
    bool ResetStream(uint64_t streamId, uint16_t errorCode);

    /**
     * \brief Ask the peer to stop sending on a stream (STOP_SENDING, RFC 9000 s19.5)
     * \param streamId the stream
     * \param errorCode application error code
     * \return true if the request was issued
     */
    bool StopSending(uint64_t streamId, uint16_t errorCode);

    /**
     * \\brief Finish the sending side of a stream: the data already written is delivered and the
     * stream ends with a FIN (msquic QUIC_SEND_FLAG_FIN / graceful stream shutdown)
     * \\param streamId the stream
     * \\return true if the FIN was queued
     */
    bool FinishStream(uint64_t streamId);

    /**
     * \brief Set the send priority of a stream (msquic QUIC_PARAM_STREAM_PRIORITY)
     *
     * Streams with a higher value are scheduled first; the default is 0x7FFF. Applies to data
     * queued after the call.
     * \param streamId the stream
     * \param priority 0..65535
     */
    void SetStreamPriority(uint64_t streamId, uint16_t priority);

    /**
     * \brief Forward a stream backlog change to the scheduler
     * \param streamId the stream
     * \param backlogged true while unsent data remains in the stream
     */
    void SetStreamBacklog(uint64_t streamId, bool backlogged);

    /**
     * \\brief Whether an ACK is queued or its delay timer is running
     * \\return true if an ACK is about to be sent
     */
    /**
     * \\brief Whether a packet ending with this token is a stateless reset for this connection
     * \\param hi upper 64 bits
     * \\param lo lower 64 bits
     * \\return true on a match with the token the peer announced
     */
    bool MatchesStatelessReset(uint64_t hi, uint64_t lo) const
    {
        if (m_hasPeerResetToken && hi == m_peerResetTokenHi && lo == m_peerResetTokenLo)
        {
            return true;
        }
        for (auto& cid : m_dstCids)
        {
            if (cid.tokenHi == hi && cid.tokenLo == lo && (hi != 0 || lo != 0))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * \\brief The peer reset the connection (msquic: silent close, status aborted)
     */
    void HandleStatelessReset(void);

    /** \\return true if this socket is the server side of its connection (it accepted it) */
    bool IsServerSide(void) const
    {
        return m_isServerSide;
    }

    /**
     * \\brief Called by the L4 protocol for every short header packet: find or create the packet's
     * path (msquic QuicConnGetPathForPacket)
     * \\param udp the UDP socket the packet arrived on
     * \\param from the sender address
     * \\param bytes the size of the datagram
     * \\param connectionId the destination connection id of the packet
     * \\return false if the packet must be dropped
     */
    bool OnPacketOnPath(Ptr<Socket> udp,
                        const Address& from,
                        uint32_t bytes,
                        const QuicConnectionId& connectionId);

    /** \\brief Note a frame of the packet being processed (non-probing frames can start a
     * migration) */
    void NoteFrame(const QuicSubheader& sub);

    /**
     * \\brief Move the connection to a new local address (client migration / rebind), like msquic
     * QUIC_PARAM_CONN_LOCAL_ADDRESS: a new UDP socket replaces the old one and a PING goes out; the
     * peer validates the new path
     * \\param newLocal the new local address; port 0 picks an ephemeral port
     * \\return true if the connection moved
     */
    bool Migrate(const Address& newLocal);

    /** \\return the number of paths the connection tracks */
    size_t GetPathCount(void) const
    {
        return m_paths.size();
    }

    /** \\return true if the active path is validated */
    bool IsActivePathValidated(void) const
    {
        return m_paths.empty() || m_paths.front().validated;
    }

    /** \\return the remote address of the active path */
    Address GetActiveRemote(void) const
    {
        return m_paths.empty() ? Address() : m_paths.front().remote;
    }

    /** \\return the number of connection ids this endpoint issued that are still usable */
    uint32_t GetActiveSourceCids(void) const;

    /** \\return the number of connection ids the peer issued that are still usable */
    uint32_t GetActiveDestCids(void) const;

    /** \\return the destination connection id used on the active path */
    QuicConnectionId GetDestCid(void) const
    {
        return m_destCid.IsEmpty() ? m_connectionId : m_destCid;
    }

    /** \\return the congestion window in bytes */
    uint32_t GetCongestionWindowBytes(void) const
    {
        return m_tcb->m_cWnd.Get();
    }

    /** \\return the current segment size (path MTU minus headers) */
    uint32_t GetPathSegmentSize(void) const
    {
        return m_tcb->m_segmentSize;
    }

    /**
     * \\brief Mark this socket as the server side of the connection
     * \\param server true for the accepting side
     */
    void SetServerSide(bool server)
    {
        m_isServerSide = server;
    }

    /**
     * \\brief Stream limit announced by the peer: how many streams of a kind this endpoint may open
     * \\param bidirectional true for bidirectional streams, false for unidirectional
     * \\return the number of streams
     */
    uint64_t GetPeerMaxStreams(bool bidirectional) const
    {
        return m_peerMaxStreams[bidirectional ? 0 : 1];
    }

    /**
     * \\brief Stream limit this endpoint announced: how many streams of a kind the peer may open
     * \\param bidirectional true for bidirectional streams, false for unidirectional
     * \\return the number of streams
     */
    uint64_t GetOwnMaxStreams(bool bidirectional) const
    {
        return bidirectional ? m_initial_max_stream_id_bidi : m_initial_max_stream_id_uni;
    }

    /**
     * \\brief Limit on the bytes this endpoint may send on a new stream (RFC 9000 s18.2)
     * \\param locallyInitiated whether this endpoint opened the stream
     * \\param bidirectional whether the stream is bidirectional
     * \\return the initial limit announced by the peer
     */
    uint64_t GetPeerStreamDataLimit(bool locallyInitiated, bool bidirectional) const
    {
        if (!bidirectional)
        {
            return locallyInitiated ? m_peerStreamData[2] : 0;
        }
        return locallyInitiated ? m_peerStreamData[1] : m_peerStreamData[0];
    }

    /**
     * \\brief Receive window this endpoint announces for a new stream
     * \\param locallyInitiated whether this endpoint opened the stream
     * \\param bidirectional whether the stream is bidirectional
     * \\return the initial window
     */
    uint64_t GetOwnStreamRecvWindow(bool locallyInitiated, bool bidirectional) const
    {
        return m_initial_max_stream_data;
    }

    /**
     * \\brief Allow the peer one more stream after one of its streams finished (MAX_STREAMS)
     * \\param bidirectional the kind of stream
     */
    void GrantPeerStream(bool bidirectional);

    uint8_t GetAckTolerance(void) const
    {
        return m_ackTolerance;
    }

    /**
     * \brief Number of ack-eliciting packets the peer may receive before it must ACK (as requested
     * by us)
     * \return the tolerance
     */
    uint8_t GetPeerAckTolerance(void) const
    {
        return m_peerAckTolerance;
    }

    bool HasAckPending() const
    {
        return m_queue_ack || m_delAckEvent.IsPending() || m_sendAckEvent.IsPending();
    }

    /**
     * \brief Get the stream multiplexing layer of this connection
     * \return the L5 protocol object
     */
    Ptr<QuicL5Protocol> GetQuicL5(void) const
    {
        return m_quicl5;
    }

    virtual int ShutdownRecv(void);
    virtual void SetNode(Ptr<Node> node);
    virtual Ptr<Node> GetNode(void) const;
    virtual int GetSockName(Address& address) const;
    virtual int GetPeerName(Address& address) const;
    virtual uint32_t GetTxAvailable(void) const;
    virtual uint32_t GetRxAvailable(void) const;
    virtual enum SocketErrno GetErrno(void) const;
    virtual enum SocketType GetSocketType(void) const;

    /**
     * Set the latency bound for a specified stream
     *
     * \param streamId The stream ID
     * \param latency The stream's maximum latency
     */
    void SetLatency(uint32_t streamId, Time latency);

    /**
     * Get the latency bound for a specified stream
     *
     * \param streamId The stream ID
     * \return The stream's maximum latency, or 0 if the stream is not registered
     */
    Time GetLatency(uint32_t streamId);

    /**
     * Set the default latency bound
     *
     * \param latency The default maximum latency
     */
    void SetDefaultLatency(Time latency);

    /**
     * Get the default latency bound
     *
     * \param streamId The stream ID
     * \return The default maximum latency
     */
    Time GetDefaultLatency();

    /**
     * \brief TracedCallback signature for QUIC packet transmission or reception events.
     *
     * \param [in] packet The packet.
     * \param [in] header The QuicHeaders
     * \param [in] socket This socket
     */
    typedef void (*QuicTxRxTracedCallback)(const Ptr<const Packet> packet,
                                           const QuicHeader& header,
                                           const Ptr<const QuicSocketBase> socket);

  protected:
    // Implementation of QuicSocket virtuals
    virtual bool SetAllowBroadcast(bool allowBroadcast);
    virtual bool GetAllowBroadcast(void) const;

    /**
     * \brief Creates a Quic L5 Protocol
     *
     * \return the created Quic L5 Protocol
     */
    Ptr<QuicL5Protocol> CreateStreamController();

    /**
     * \brief RFC 9002 §9.1 / RFC 9001 §4.9: Discard Initial packet number space.
     *
     * Clears the loss-time and largest-acked for the Initial space, and marks
     * m_initialSpaceDiscarded.  Called when the first Handshake packet is sent or
     * received (i.e., the INITIAL_SPACE keys are no longer needed).
     */
    void DiscardInitialPacketSpace();

    /**
     * \brief RFC 9002 §9.1 / RFC 9001 §4.9: Discard Handshake packet number space.
     *
     * Clears the loss-time and largest-acked for the Handshake space, and marks
     * m_handshakeSpaceDiscarded.  Called when the handshake is confirmed (both
     * endpoints reach OPEN state).
     */
    void DiscardHandshakePacketSpace();

    /**
     * \brief RFC 9002 §2: Map a QuicHeader to the corresponding PacketNumberSpace.
     *
     * - IsInitial()  → INITIAL_SPACE
     * - IsHandshake() → HANDSHAKE_SPACE
     * - IsShort() or IsORTT() → APP_DATA_SPACE
     *
     * \param header The QuicHeader of the packet
     * \return the PacketNumberSpace for this header type
     */
    static PacketNumberSpace GetPacketNumberSpace(const QuicHeader& header);

    /**
     * \brief Set the RTO timer (called when packets or ACKs are sent)
     */
    void SetReTxTimeout();

    /**
     * \brief The probe timeout before backoff (RFC 9002 s6.2.1)
     *
     * \param withMaxAckDelay add the peer's max_ack_delay (Application Data space); false for the
     *        Initial and Handshake spaces
     * \return smoothed_rtt + max (4 * rttvar, kGranularity) [+ max_ack_delay], with kInitialRtt in
     * place of the RTT estimate until the first sample
     */
    Time ProbeTimeout(bool withMaxAckDelay) const;

    /**
     * Time a connection that closes stays in the closing state, absorbing the late packets of the
     * peer (RFC 9000 s10.2.1 and s10.2.2: at least three PTOs).
     *
     * @return three times the PTO of the Application Data space
     */
    Time ClosingPeriod() const;

    /**
     * The idle timer expired. A connection still in the handshake is abandoned and the application
     * hears that it failed (RFC 9000 s10.1); an established one closes as Close () does.
     */
    void IdleTimeoutExpired();

    /**
     * Send a PING on an otherwise silent connection, so that the idle timers of both ends are
     * restarted by the answer (RFC 9000 s10.1.2).
     */
    void SendKeepAlive();

    /**
     * \brief Record a received packet number and, when it is the largest, its arrival time
     * \param packetNumber the packet number
     */
    void NotePacketReceived(uint32_t packetNumber);

    /**
     * \brief Enter the draining state after a CONNECTION_CLOSE from the peer (RFC 9000 s10.2.2)
     */
    void EnterDraining();

    /**
     * \brief Tell the application that the peer closed the connection (once)
     */
    void NotifyClosedByPeer();

    /**
     * \brief (Re)start the idle timer: max_idle_timeout, or three PTOs if that is longer (RFC 9000
     * s10.1)
     */
    void ArmIdleTimer();

    /**
     * Client: arm the timer that repeats the Handshake packet until HANDSHAKE_DONE arrives (RFC
     * 9001 s4.9.2: a client keeps its Handshake keys until the handshake is confirmed, so the
     * packet that completes the server's handshake can be sent again)
     */
    void ArmHandshakeResend();

    /** The Handshake packet was not answered in time: send another one */
    void HandshakeResendTimeout();

    /**
     * \brief True while the idle timer is running (or the connection is open with the timer
     * disabled)
     */
    bool IdleTimerArmed() const;

    /**
     * \brief Handle what happens in case of an RTO
     */
    void ReTxTimeout();

    /**
     * \brief Handle retransmission after loss
     */
    uint64_t m_peerMaxData{
        0}; //!< Peer connection limit (absolute, from transport parameters and MAX_DATA)
    uint32_t m_peerInitialMaxStreamData{0}; //!< Peer's initial per-stream limit
    bool m_closeAfterHandshake{false}; //!< Close() was called during the handshake: close once OPEN
    Time m_ptoEpisodeStart{Seconds(0)}; //!< When the current run of unanswered PTOs began
    Time m_disconnectTimeout{
        Seconds(16)}; //!< Give up after this long without ACK progress (msquic default)
    std::set<uint32_t>
        m_declaredLost; //!< Numbers of packets declared lost, for spurious-loss detection
    /**
     * \brief Detect acknowledgments of packets previously declared lost
     * \param largest largest acknowledged
     * \param blocks additional ack blocks
     * \param gaps gaps
     */
    void CheckSpuriousLosses(uint32_t largest,
                             const std::vector<uint32_t>& blocks,
                             const std::vector<uint32_t>& gaps,
                             uint32_t ackFloor);
    void DoRetransmit(std::vector<Ptr<QuicSocketTxItem>> lostPackets, bool exempt = false);

    /**
     * \brief Extract at most maxSize bytes from the TxBuffer at sequence packetNumber, add the
     *        QUIC header, and send to QuicL4Protocol
     *
     * According to the internal state of the socket, a different header is built.
     * Sequence numbers should be 64 bits in the QUIC standard, but we use 32 to
     * be compatible with the TcpSocketBase class
     *
     * \param seq the sequence number
     * \param maxSize the maximum data block to be transmitted (in bytes)
     * \param withAck forces an ACK to be sent
     * \returns the number of bytes sent
     */
    uint32_t SendDataPacket(SequenceNumber32 packetNumber, uint32_t maxSize, bool withAck);

    /**
     * \brief Send a Connection Close frame
     *
     * \param errorCode the error code that caused the connection close event
     * \param phrase human-readable error description
     * \return 0 on success
     */
    uint32_t SendConnectionClosePacket(uint16_t errorCode, std::string phrase);

    /**
     * \brief Send as much pending data as possible according to the Tx window.
     *
     * \param withAck forces an ACK to be sent
     * \return the number of packets sent
     */
    uint32_t SendPendingData(bool withAck = false);

    /**
     * \brief Record whether an acknowledged packet lies between the lost ones (persistent
     * congestion check)
     * \param lostPackets the packets declared lost
     */
    void UpdateLostSpanState(const std::vector<Ptr<QuicSocketTxItem>>& lostPackets);

    /**
     * \brief Perform the real connection tasks: start the initial handshake for non-0-RTT
     *
     * \return 0 on success
     */
    int DoConnect(void);

    /**
     * \brief Perform the real connection tasks: start the initial 0-RTT handshake
     *
     * \return 0 on success
     */
    int DoFastConnect(void);

    /**
     * \brief Set the socket to IDLE, nullify the callbacks and remove this socket from the
     * QuicL4Protocol
     *
     * \return 1 on success
     */
    int DoClose(void);

    /**
     * \brief receive a QUIC packet
     *
     * \param p a smart pointer to a packet
     * \param quicHeader the header of the packet
     * \param address the Address from which the packet was received
     */
    void ReceivedData(Ptr<Packet> p, const QuicHeader& quicHeader, Address& address);

    /**
     * \brief Update the state of the internal state machine
     *
     * \param the new state
     */
    void SetState(TracedValue<QuicStates_t> state);

    /**
     * \brief Check if a version is supported by the QuicSocket
     *
     * \param version the version to be checked
     */
    bool IsVersionSupported(uint32_t version);

    /**
     * \brief Check if there are missing packets in the m_receivedPacketNumbers list
     *
     * \return true if there are missing packets
     */
    bool HasReceivedMissing();

    std::map<uint64_t, uint16_t> m_streamPriorities; //!< Priorities set by the application
    // DPLPMTUD (msquic mtu_discovery.c): start at a 1288 byte IP MTU, probe +80 bytes at a time up
    // to the maximum (1500 is always tried); a size missed 3 times ends the search.
    bool m_pmtudEnabled{true}; //!< Attribute EnableMtuDiscovery
    uint32_t m_pmtudMaxSeg{
        0}; //!< Largest segment size allowed on the path (configured segment size)
    uint32_t m_pmtudProbeMtu{0};   //!< IP MTU being probed
    uint32_t m_pmtudProbeCount{0}; //!< Probes sent at this size
    uint32_t m_pmtudProbePn{0};    //!< Packet number of the outstanding probe (0 = none)
    bool m_pmtudStarted{false};    //!< Initial MTU already applied
    bool m_pmtudSearchDone{true};  //!< Search finished or not started
    EventId m_pmtudTimeout;        //!< The outstanding probe is considered lost
    static constexpr uint32_t kPmtudInitialMtu =
        1288; //!< QUIC_DPLPMTUD_DEFAULT_MIN_MTU with IPv4 accounting
    static constexpr uint32_t kPmtudOverhead =
        41; //!< IP MTU minus segment size: IP 20 + UDP 8 + short QUIC header 13
    void StartMtuDiscovery(void);
    void SendMtuProbe(void);
    void OnMtuProbeTimeout(void);
    void OnMtuProbeAcked(void);
    bool m_closeNotified{false};   //!< The application was already told that the connection ended
    bool m_closePacketSent{false}; //!< A CONNECTION_CLOSE left after a local close: the closing
                                   //!< state of RFC 9000 s10.2.1
    uint32_t m_closingPacketsReceived{
        0}; //!< Packets received while closing, to pace the repeats of CONNECTION_CLOSE
    Address m_connectAddress;       //!< Address a client connected to, to look up the parameters
                                    //!< remembered for it
    EventId m_handshakeResendEvent; //!< Client: repeats the Handshake packet until HANDSHAKE_DONE
                                    //!< arrives
    uint32_t m_handshakeResendCount{
        0}; //!< Client: times the Handshake packet was repeated (the backoff exponent)
    bool m_handshakeResendPending{false}; //!< The next packet sent carries a Handshake header
    bool m_handshakeDoneReceived{
        false}; //!< Client: HANDSHAKE_DONE arrived, the handshake is confirmed
    static constexpr uint32_t kMaxHandshakeResends =
        8; //!< Handshake packets repeated before the client relies on the idle timeout

    // ACK frequency (draft-ietf-quic-ack-frequency), as msquic: always advertised, adjusted by the
    // sender
    // ---- Connection ids and paths (RFC 9000 s5.1, s8.2, s9; msquic connection.c, path.c) ----
    /** A connection id and its sequence number, with the stateless reset token that goes with it */
    struct QuicCidEntry
    {
        uint64_t sequence{0};
        QuicConnectionId id;
        uint64_t tokenHi{0};
        uint64_t tokenLo{0};
        bool retired{false};
        bool used{false}; //!< source ids: the peer used it; destination ids: we used it
    };

    /** A network path of the connection: a remote address reached through a local UDP socket */
    struct QuicPath
    {
        uint32_t id{0};
        Address remote;
        Ptr<Socket> udp;
        bool active{false};
        bool validated{false};
        bool gotValidPacket{false};
        bool sendChallenge{false};
        uint64_t challenge{0};
        Time validationStart;
        Time lastChallengeSent;
        uint64_t allowance{0}; //!< bytes that may still be sent while the path is not validated
        int64_t destCidSequence{-1}; //!< destination connection id used on this path
        bool initiatedCidUpdate{false};
        uint32_t segSize{0}; //!< segment size of the path while it is not active
        uint32_t maxSeg{0};
        bool mtuSearchDone{true};
        bool mtuStarted{false};
    };

    std::vector<QuicCidEntry> m_srcCids; //!< ids we issued (the peer puts them in packets for us)
    std::vector<QuicCidEntry>
        m_dstCids;                    //!< ids the peer issued (we put them in packets for the peer)
    uint64_t m_nextSrcCidSequence{1}; //!< sequence number of the next id we issue
    uint64_t m_peerRetirePriorTo{0};  //!< highest retire-prior-to the peer announced
    uint8_t m_peerActiveCidLimit{2};  //!< active_connection_id_limit announced by the peer
    QuicConnectionId m_destCid;       //!< destination id of the active path
    std::vector<QuicPath> m_paths;    //!< paths; the active one is first
    uint32_t m_nextPathId{1};         //!< id of the next path
    int m_rxPathIndex{-1};            //!< path of the packet being processed
    QuicConnectionId m_rxDcid;        //!< destination id carried by the packet being processed
    bool m_rxNonProbing{false};       //!< the packet being processed holds a non-probing frame
    EventId m_pathTimer;              //!< path validation: challenge retransmission and timeout
    static constexpr uint32_t kMaxPaths = 4;      //!< QUIC_MAX_PATH_COUNT
    static constexpr uint8_t kActiveCidLimit = 4; //!< QUIC_ACTIVE_CONNECTION_ID_LIMIT
    static constexpr uint32_t kMinSendAllowance =
        76; //!< QUIC_MIN_SEND_ALLOWANCE: smallest packet worth sending on an unvalidated path
    static constexpr uint32_t kChallengeReserve =
        2 * kMinSendAllowance; //!< allowance data leaves alone on an unvalidated path while a
                               //!< PATH_CHALLENGE is pending, to repeat it

    Time m_destCidUpdateIdleTimeout{Seconds(20)}; //!< Attribute DestCidUpdateIdleTimeout
    Time m_lastPacketSent{Seconds(0)};            //!< When this endpoint last sent a packet
    void MaybeUpdateDestCid(void);
    void InitPaths(void);
    void IssueSourceCids(void);
    void IssueSourceCid(void);
    QuicCidEntry* FindSourceCid(const QuicConnectionId& id);
    QuicCidEntry* UnusedDestCid(void);
    bool RetireCurrentDestCid(QuicPath& path);
    void RetireDestCid(QuicCidEntry& cid);
    QuicConnectionId PathDestCid(QuicPath& path);
    void SendControlFrame(const QuicSubheader& sub);
    void SendPathChallenge(QuicPath& path);
    void SendPathResponse(QuicPath& path, uint64_t data);
    void RecvPostProcessing(void);
    void ActivatePath(size_t index);
    void OnPathValidationTimer(void);
    void ArmPathTimer(void);
    Time PathValidationTimeout(void) const;
    Time PathProbeTimeout(void) const;
    void RemovePath(size_t index);
    void SetPathValid(QuicPath& path);
    bool IsProbingFrame(const QuicSubheader& sub) const;
    bool m_isServerSide{false};      //!< This socket accepted the connection
    uint32_t m_pendingWriteBytes{0}; //!< Bytes held in m_pendingWrites
    std::vector<std::pair<Ptr<Packet>, uint64_t>>
        m_pendingWrites; //!< Application writes made before the handshake ended
    int SendOnStream(Ptr<Packet> p, uint64_t streamId);
    uint64_t m_peerMaxStreams[2]{0,
                                 0}; //!< Streams we may open: [0] bidirectional, [1] unidirectional
    uint64_t m_peerStreamData[3]{0,
                                 0,
                                 0}; //!< Peer stream data limits: bidi local, bidi remote, uni
    uint64_t m_streamsBlockedAt[2]{UINT64_MAX,
                                   UINT64_MAX}; //!< Limit for which STREAMS_BLOCKED was sent
    bool m_hasPeerResetToken{false};            //!< The peer announced a stateless reset token
    uint64_t m_peerResetTokenHi{0};             //!< Upper 64 bits of the peer token
    uint64_t m_peerResetTokenLo{0};             //!< Lower 64 bits of the peer token
    uint8_t m_ackTolerance{2}; //!< ack-eliciting packets received before an ACK is due (our side)
    uint8_t m_ackReorderingThreshold{1}; //!< hole size that makes us ACK at once (our side)
    uint8_t m_peerAckTolerance{2};       //!< tolerance we asked the peer to use
    uint8_t m_peerAckReordering{1};      //!< reordering threshold we asked the peer to use
    uint64_t m_sendAckFreqSeq{0};        //!< sequence number of the last ACK_FREQUENCY we sent
    uint64_t m_nextRecvAckFreqSeq{0};    //!< next ACK_FREQUENCY sequence number we accept
    bool m_peerSupportsAckFreq{false};   //!< the peer advertised min_ack_delay
    bool m_immediateAckRequested{
        false}; //!< an IMMEDIATE_ACK frame arrived in the packet being processed
    static constexpr uint32_t kMaxDatagramsPerSend = 40; //!< QUIC_MAX_DATAGRAMS_PER_SEND
    void UpdatePeerAckTolerance(uint8_t tolerance);

    /**
     * \brief Most ACK-eliciting packets the peer may be asked to wait for before acknowledging
     *
     * With a window smaller than the tolerance the peer cannot reach it and acknowledges on its
     * delayed-ACK timer instead, which stalls the ACK clock. The limit keeps several ACKs per round
     * trip, whatever the window did since the tolerance was raised.
     * \return the limit, at least 2
     */
    uint32_t AckToleranceLimit() const;

    /** Lower the ACK tolerance asked of the peer when the window no longer holds that many packets
     */
    void ClampPeerAckTolerance();

    /**
     * Size of the ACK frame that the next packet would carry
     * \param withAck whether the next packet carries an ACK frame
     * \return the size in bytes, 0 when there is nothing to acknowledge
     */
    uint32_t PendingAckFrameSize(bool withAck);
    uint32_t m_latestRecvPn{0};       //!< Packet number of the last packet received
    uint32_t m_largestPnAckedByUs{0}; //!< Largest packet number reported in an ACK frame we sent

    /**
     * \brief Send an ACK packet
     */
    void SendAck();

    /**
     * \brief Call Socket::NotifyConnectionSucceeded()
     */
    void ConnectionSucceeded(void);

    /**
     * \brief Notify Pacing
     */
    void NotifyPacingPerformed(void);
    /**
     * Send the connection close packet and schedule
     * the DoClose method
     */
    void ScheduleCloseAndSendConnectionClosePacket();

    // Connections to other layers of the Stack
    Ipv4EndPoint* m_endPoint;     //!< the IPv4 endpoint
    Ipv6EndPoint* m_endPoint6;    //!< the IPv6 endpoint
    Ptr<Node> m_node;             //!< The associated node
    Ptr<QuicL4Protocol> m_quicl4; //!< The associated L4 Protocol
    Ptr<QuicL5Protocol> m_quicl5; //!< The associated L5 Protocol
    TracedCallback<uint32_t>
        m_spuriousLossTrace; //!< Fired when a packet declared lost is later acknowledged

    // Rx and Tx buffer management
    Ptr<QuicSocketRxBuffer> m_rxBuffer;   //!< RX buffer
    Ptr<QuicSocketTxBuffer> m_txBuffer;   //!< TX buffer
    uint32_t m_socketTxBufferSize;        //!< Size of the socket TX buffer
    uint32_t m_socketRxBufferSize;        //!< Size of the socket RX buffer
    QuicPnRanges m_receivedPacketNumbers; //!< Received packet numbers
    TypeId m_schedulingTypeId;            //!< The socket type of the packet scheduler
    Time m_defaultLatency; //!< The default latency bound (only used by the EDF scheduler)

    // State-related attributes
    TracedValue<QuicStates_t> m_socketState; //!< State in the Congestion state machine
    uint16_t m_transportErrorCode;           //!< Quic transport error code
    bool m_serverBusy;                       //!< If true, server too busy to accept new connections
    mutable enum SocketErrno m_errno;        //!< Socket error code
    bool m_connected;                        //!< Check if connection is established
    bool m_zeroRttConnect; //!< True on a client socket that connected with a 0-RTT handshake
    QuicConnectionId m_connectionId;   //!< Connection id
    uint32_t m_vers;                   //!< Quic protocol version
    QuicHeader::KeyPhase_t m_keyPhase; //!< Key phase
    bool m_spinBit;                    //!< Spin bit for latency measurement (RFC 9000 §17.3.1)
    Time m_lastReceived;               //!< Time of last received packet
    Time m_largestRecvTime; //!< Arrival time of the largest packet number received (ack delay is
                            //!< measured from it)
    uint64_t m_bytesReceivedPreValidation; //!< Bytes received before peer address validation (RFC
                                           //!< 9000 §8)
    uint64_t m_bytesSentPreValidation; //!< Bytes sent before peer address validation (RFC 9000 §8)
    bool m_peerAddressValidated;       //!< True once peer address is validated (RFC 9000 §8)

    // RFC 9002 §2: packet number space of the packet currently being received.
    // Set in ReceivedData() before DispatchRecv() so OnReceivedAckFrame() can
    // update the correct per-space m_largestAckedPacketSpace entry.
    PacketNumberSpace m_currentRecvPacketNumberSpace{APP_DATA_SPACE};

    // RFC 9002 §9.1 / RFC 9001 §4.9: key discard per packet number space.
    bool m_initialSpaceDiscarded{false};   //!< True once Initial space keys are discarded
    bool m_handshakeSpaceDiscarded{false}; //!< True once Handshake space keys are discarded

    // Transport Parameters values
    uint32_t m_initial_max_stream_data; //!< initial_max_stream_data_bidi_local (0x05): max data on
                                        //!< locally-initiated bidi streams
    uint32_t m_initial_max_stream_data_bidi_remote; //!< initial_max_stream_data_bidi_remote (RFC
                                                    //!< 9000 §18.2, 0x06)
    uint32_t m_initial_max_stream_data_uni; //!< initial_max_stream_data_uni (RFC 9000 §18.2, 0x07)
    uint32_t m_max_data; //!< The maximum amount of data that can be sent on the connection
    uint32_t m_initial_max_stream_id_bidi; //!< The the initial maximum number of application-owned
                                           //!< bidirectional streams the peer may initiate
    TracedValue<Time> m_idleTimeout; //!< Idle timeout; 0 disables it (the negotiated value once the
                                     //!< transport parameters are in)
    Time m_keepAliveInterval;  //!< Time without a received packet after which a PING is sent; 0
                               //!< disables the keep-alive
    bool m_omit_connection_id; //!< The flag that indicates if the connection id is required in the
                               //!< upcoming connection
    /*uint128_t  m_stateless_reset_token;*/ //!< The stateless reset token
    uint8_t m_ack_delay_exponent; //!< Our ack_delay_exponent: scales the ack delay of the ACK
                                  //!< frames we send (RFC 9000 s19.3)
    bool m_disableActiveMigration{
        false}; //!< Announce disable_active_migration in our transport parameters (RFC 9000 s18.2)
    bool m_peerDisablesMigration{
        false}; //!< The peer announced disable_active_migration: this endpoint must not migrate
    uint8_t m_peerAckDelayExponent{
        3}; //!< The peer's ack_delay_exponent: decodes the ack delay of the ACK frames it sends
    uint32_t m_initial_max_stream_id_uni; //!< The initial maximum number of application-owned
                                          //!< unidirectional streams the peer may initiate
    uint32_t m_maxTrackedGaps;            //!< The maximum number of gaps in an ACK
    uint32_t m_ackToleranceCwndDivisor;   //!< The tolerance asked of the peer is at most the window
                                          //!< in packets divided by this (0: no limit)

    // Transport Parameters management
    bool m_receivedTransportParameters; //!< Check if Transport Parameters are already been received
    bool m_couldContainTransportParameters; //!< Check if in the actual conditions can receive
                                            //!< Transport Parameters

    // Timers and Events
    EventId m_sendPendingDataEvent; //!< Micro-delay event to send pending data
    EventId m_retxEvent;            //!< Retransmission event
    EventId m_keepAliveEvent;       //!< Event that sends the keep-alive PING
    EventId m_idleTimeoutEvent;     //!< Event triggered upon receiving or sending a packet, when it
                                    //!< expires the connection closes
    EventId m_drainingPeriodEvent;  //!< Event triggered upon idle timeout or immediate connection
                                    //!< close, when it expires all closes
    TracedValue<Time> m_rto;        //!< Retransmit timeout
    EventId m_sendAckEvent;         //!< Send ACK timeout event
    EventId m_delAckEvent;          //!< Delayed ACK timeout event
    bool m_flushOnClose;            //!< Control behavior on connection close
    bool m_closeOnEmpty; //!< True if the socket will close after sending the buffered packets

    // Congestion Control
    Ptr<QuicSocketState> m_tcb;                //!< Congestion control informations
    Ptr<TcpCongestionOps> m_congestionControl; //!< Congestion control
    TracedValue<Time> m_lastRtt;               //!< Latest measured RTT
    bool m_quicCongestionControlLegacy; //!< Quic Congestion control if true, TCP Congestion control
                                        //!< if false
    bool m_queue_ack;                   //!< Indicates a request for a queue ACK if true
    uint32_t
        m_numPacketsReceivedSinceLastAckSent; //!< Number of packets received since last ACK sent
    uint32_t m_lastMaxData;                   //!< Last MaxData ACK
    uint32_t m_maxDataInterval; //!< Interval between successive MaxData frames in ACKs

    uint32_t m_initialPacketSize; //!< size of the first packet to be sent durin the handshake (at
                                  //!< least 1200 bytes, per RFC)

    // Pacing timer
    Timer m_pacingTimer{Timer::REMOVE_ON_DESTROY}; //!< Pacing Event (1 ms chunk interval)
    Time m_lastFlushTime{Seconds(0)};              //!< msquic Send.LastFlushTime
    bool m_lastFlushValid{false};                  //!< msquic Send.LastFlushTimeValid
    uint32_t m_lastSendAllowance{0};               //!< msquic Cubic->LastSendAllowance
    uint64_t m_flushAllowance{
        UINT64_MAX}; //!< Bytes this flush may still send (msquic Builder.SendAllowance)

    /**
     * \brief Compute the pacing allowance of a new flush (msquic
     * CubicCongestionControlGetSendAllowance)
     */
    void BeginSendFlush(void);

    /**
     * \brief Account for bytes sent in the current flush
     * \param bytes packet size
     */
    void ConsumeSendAllowance(uint32_t bytes);

    /**
     * \brief Callback pointer for cWnd trace chaining
     */
    TracedCallback<uint32_t, uint32_t> m_cWndTrace;

    /**
     * \brief Callback pointer for ssTh trace chaining
     */
    TracedCallback<uint32_t, uint32_t> m_ssThTrace;

    /**
     * \brief Callback pointer for congestion state trace chaining
     */
    TracedCallback<TcpSocketState::TcpCongState_t, TcpSocketState::TcpCongState_t> m_congStateTrace;

    /**
     * \brief Callback pointer for high transmission mark trace chaining
     */
    TracedCallback<uint32_t, uint32_t> m_highTxMarkTrace;

    /**
     * \brief Callback pointer for tx sequence trace chaining
     */
    TracedCallback<uint32_t, uint32_t> m_nextTxSequenceTrace;

    // The following two traces pass a packet with a QUIC header
    TracedCallback<Ptr<const Packet>,
                   const QuicHeader&,
                   Ptr<const QuicSocketBase>>
        m_txTrace; //!< Trace of transmitted packets

    TracedCallback<Ptr<const Packet>,
                   const QuicHeader&,
                   Ptr<const QuicSocketBase>>
        m_rxTrace; //!< Trace of received packets
};

} // namespace ns3
#endif /* QUIC_SOCKET_BASE_H_ */
