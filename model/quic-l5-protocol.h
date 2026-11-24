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

#ifndef QUICL5PROTOCOL_H
#define QUICL5PROTOCOL_H

#include "quic-stream.h"
#include "quic-subheader.h"
#include "quic-transport-parameters.h"

namespace ns3
{

class QuicSocketBase;
class QuicStreamBase;

/**
 * This class handles the creation and management of QUIC streams
 * and is associated to a QuicSocketBase object
 */

/**
 * \ingroup quic
 * \brief QUIC stream creation and multiplexing/demultiplexing
 *
 * This class is responsible for
 * - the creation of QUIC streams
 * - the binding of the QUIC socket to the QUIC streams
 *
 * The creation of QuicStreams are handled in the method CreateStream.
 * Upon creation, this class is responsible to the stream initialization and
 * handle multiplexing/demultiplexing of data. Demultiplexing is done by
 * receiving packets from a QUIC Socket, and forwards them to its associated
 * streams. Multiplexing is done through the DispatchSend function, which sends
 * the frames down the stack.
 *
 * \see CreateStream
 * \see DispatchSend
 */
class QuicL5Protocol : public Object
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    QuicL5Protocol();
    virtual ~QuicL5Protocol();

    /**
     * \brief Set the Quic Socket associated with this stack
     *
     * \param sock a smart pointer to the Quic Socket to be associated with
     */
    void SetSocket(Ptr<QuicSocketBase> sock);

    /**
     * \brief Set the node associated with this stack
     *
     * \param node the node to be associated with
     */
    void SetNode(Ptr<Node> node);

    /**
     * \brief Set the connection id associated with this stack
     *
     * \param connId the connection id to be associated with
     */
    void SetConnectionId(uint64_t connId);

    /**
     * \brief Send a packet to the streams associated to this L5 protocol
     *
     * The streams are created if not present. Stream 0 is not used (only for handshake)
     *
     * \param data a smart pointer to a packet
     * \return always 0
     */
    int DispatchSend(Ptr<Packet> data);

    /**
     * \brief Send a packet to a specific stream
     *
     * The streams is created if not present.
     *
     * \param data a smart pointer to a packet
     * \param streamId the stream ID for the packet
     * \return always 0
     */
    int DispatchSend(Ptr<Packet> data, uint64_t streamId);

    /**
     * \brief Receive a packet from the QUIC socket implementation
     *
     * The packet is disgregated into multiple frames.
     * If a frame needs to be processed by the socket, it is sent back to the socket,
     * otherwise is forwarded to the correct stream
     *
     * \param data a smart pointer to a Packet
     * \param address the sender address
     * \return 0 if the received packet was ACK-only, -1 in case of errors, 1 if everything was OK;
     */
    int DispatchRecv(Ptr<Packet> data, Address& address);

    // int DispatchRecv(Ptr<Packet> data, uint64_t streamId, Address &address);

    /**
     * \brief Method called by a stream implementation to return a proper stream frame
     * with a subheader for the frame
     *
     * \param frame a smart pointer to a packet
     * \return the size of the frame
     */
    int Send(Ptr<Packet> frame);

    /**
     * \brief Method called by a stream implementation to return a received frame (without header)
     *
     * \param frame a smart pointer to the frame
     * \param address the address of the sender
     * \return the frame size
     */
    int Recv(Ptr<Packet> frame, Address& address);

    /**
     * \brief Create a vector with fragments of packets to be sent in different streams
     *
     * \param data a smart pointer to a Packet
     * \return a vector of packet fragmets
     */
    std::vector<Ptr<Packet>> DisgregateSend(Ptr<Packet> data);

    /**
     * \brief Create a vector of frames, corresponding to frames of different streams aggregated in
     * a single QUIC packet
     *
     * \param data a smart pointer to the received packet
     * \return a vector of pairs with frames as smart pointers to packets and subheaders
     */
    std::vector<std::pair<Ptr<Packet>, QuicSubheader>> DisgregateRecv(Ptr<Packet> data);

    /**
     * \brief get the stream associated to the ID
     *
     * \param streamId the ID of the stream
     * \return a smart pointer to the stream object
     */
    Ptr<QuicStreamBase> SearchStream(uint64_t streamId);

    /**
     * \brief Create the stream that carries the handshake (internal id
     * QuicStream::HANDSHAKE_STREAM_ID)
     */
    void CreateHandshakeStream(void);

    /**
     * \brief Apply the stream data limits the peer announced to the streams that already exist
     */
    void UpdateInitialMaxStreamData(void);

    /**
     * \brief A peer-initiated stream finished in both directions: give the peer a new stream credit
     * (msquic QuicStreamSetReleaseStream) with a MAX_STREAMS frame
     * \param stream the stream
     */
    void OnStreamClosed(Ptr<QuicStreamBase> stream);

    /**
     * \brief Get the maximum packet size from the underlying socket
     *
     * \return the maximum packet size in bytes
     */
    uint16_t GetMaxPacketSize() const;

    /**
     * \brief Check with the QUIC socket if the packet that has just been received could contain
     * transport parameters
     *
     * \return a boolean, true if the packet that has just been received contains transport params
     */
    bool ContainsTransportParameters();

    /**
     * \brief Pass the transportParameters to the the QUIC socket
     *
     * \param transportParameters the QuicTransportParameters
     */
    void OnReceivedTransportParameters(QuicTransportParameters transportParameters);

    /**
     * \brief call AbortConnection in the QUIC socket implementation
     *
     * \param transportErrorCode the error code
     * \param a sentence explaining the error
     */
    void SignalAbortConnection(uint16_t transportErrorCode, const char* reasonPhrase);

    /**
     * \brief Propagate the updated max stream data values to all the streams
     *
     * \param newMaxStreamData the updated value
     */

    /**
     * \brief Return MAX_DATA for flow control (i.e., the sum of MAX_STREAM_DATA for all streams)
     *
     * \returns the new max data value
     */
    uint64_t GetMaxData();

    /**
     * \brief Connection-level send credit: peer MAX_DATA minus new stream data already sent
     * \return bytes that may still be sent
     */
    uint64_t ConnectionSendWindow() const;

    /**
     * \brief Account for new (non-retransmitted) stream data handed to the socket
     * \param bytes amount sent (negative to undo)
     */
    void OnNewDataSent(int64_t bytes);

    /**
     * \brief Account for in-order bytes delivered on any stream; sends MAX_DATA when due
     * \param bytes bytes delivered
     */
    void OnBytesDelivered(uint64_t bytes);

    /**
     * \brief The peer raised the connection limit: wake up blocked streams
     */
    void OnConnectionWindowUpdate();

    /**
     * \brief A stream could not hand a frame to the socket because the socket transmit buffer was
     * full
     */
    void NotifySocketTxFull();

    /**
     * \brief The socket sent packets and so made room in its transmit buffer: streams that a full
     * buffer turned away try again. Nothing else wakes them once the application has written
     * everything and no window update is due.
     */
    void OnSocketTxSpace();

    /**
     * \brief Reset the sending side of a stream (RESET_STREAM)
     * \param streamId the stream
     * \param errorCode application error code
     * \return true if the reset was issued
     */
    bool ResetStream(uint64_t streamId, uint16_t errorCode);

    /**
     * \brief Report that a stream has (or no longer has) unsent data in its own buffer
     * \param streamId the stream
     * \param backlogged true while data remains
     */
    void NotifyStreamBacklog(uint64_t streamId, bool backlogged);

    /**
     * \brief Whether the socket is about to send an ACK
     * \return true if an ACK is queued or its delay timer runs
     */
    bool IsAckPending() const;

    /**
     * \brief Ask the peer to stop sending on a stream (STOP_SENDING)
     * \param streamId the stream
     * \param errorCode application error code
     * \return true if the request was issued
     */
    bool StopSendingOnStream(uint64_t streamId, uint16_t errorCode);

    /**
     * \\brief Finish the sending side of a stream (FIN)
     * \\param streamId the stream
     * \\return true if the FIN was queued
     */
    bool FinishStream(uint64_t streamId);

    /**
     * \brief Smoothed RTT of the connection
     * \return the smoothed RTT
     */
    Time GetSmoothedRtt() const;

    /**
     * \brief Send DATA_BLOCKED once per limit when the connection limit stops new data
     */
    void ReportConnectionBlockedIfNeeded();

    /**
     * \brief Whether any stream still holds application data not yet handed to the socket
     * \return true if data is pending
     */
    bool HasPendingStreamData() const;

    /**
     * \brief Account for new highest stream offsets received
     * \param bytes growth of the sum of highest received offsets
     * \return false if the connection-level limit we advertised was exceeded
     */
    bool OnBytesReceivedAtOffset(uint64_t bytes);

  private:
    uint64_t m_connSent{0};                 //!< New stream data sent on the connection
    uint64_t m_connDeliveredAccumulator{0}; //!< Bytes delivered since the last MAX_DATA
    uint64_t m_connDelivered{0};            //!< In-order bytes delivered on the connection
    uint64_t m_connBlockedReportedAt{
        UINT64_MAX};              //!< Connection limit for which DATA_BLOCKED was last sent
    uint64_t m_connRecvTotal{0};  //!< Sum of highest received stream offsets
    uint64_t m_connMaxAllowed{0}; //!< Advertised MAX_DATA (0: not yet initialised)
    bool m_socketTxFull{
        false};               //!< A stream was refused by the full socket buffer and waits for room
    QuicSocketBase* m_socket; //!< The Quic socket this stack is associated with; not a Ptr, because
                              //!< the socket owns this stack and a Ptr here would be a cycle that
                              //!< keeps both alive for good
    Ptr<Node> m_node;         //!< The node this stack is associated with
    uint64_t m_connectionId;  //!< The connection id this stack is associated with
    std::vector<Ptr<QuicStreamBase>>
        m_streams; //!< The streams this stack is associated with (handshake first)
    std::map<uint64_t, Ptr<QuicStreamBase>> m_streamById; //!< The streams by RFC 9000 stream id
    uint64_t m_streamsCreated[4]{0, 0, 0, 0};             //!< Streams created per type (id & 3)

    /**
     * \brief Create a stream with the given id and the limits of its type
     * \param streamId the id
     * \return the stream
     */
    Ptr<QuicStreamBase> AddStream(uint64_t streamId);

    /**
     * \brief Whether the stream was initiated by this endpoint
     * \param streamId the id
     * \return true if locally initiated
     */
    bool IsLocallyInitiated(uint64_t streamId) const;

    /**
     * \brief Find or open a stream this endpoint initiates (RFC 9000 s3.2, s4.6)
     * \param streamId the id
     * \return the stream, or null if the peer's stream limit does not allow it yet
     */
    Ptr<QuicStreamBase> OpenLocalStream(uint64_t streamId);

    /**
     * \brief Find or create a stream the peer initiates (msquic QuicStreamSetGetStreamForPeer)
     * \param streamId the id
     * \param fatal set when the frame is a protocol violation and the connection was aborted
     * \return the stream or null
     */
    Ptr<QuicStreamBase> GetStreamForPeer(uint64_t streamId, bool& fatal);
};

} // namespace ns3

#endif /* QUIC_L5_PROTOCOL_H */
