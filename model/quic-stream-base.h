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

#ifndef QUICSTREAMBASE_H_
#define QUICSTREAMBASE_H_

#include "quic-header.h"
#include "quic-l5-protocol.h"
#include "quic-stream-rx-buffer.h"
#include "quic-stream-tx-buffer.h"
#include "quic-stream.h"
#include "quic-subheader.h"

#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/traced-value.h"

// #include "quic-frame-manager.h"

namespace ns3
{

/**
 * \ingroup quic
 *
 * \brief A base class for implementation of a QUIC stream
 *
 * This class contains the essential components of Quic Streams, as well as streams
 * interfaces to call. This class provides credit-based flow control; congestion
 * control is delegated to subclasses of QuicCongestionOps
 *
 */
class QuicStreamBase : public QuicStream
{
  public:
    /**
     * Get the type ID.
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    QuicStreamBase(void);
    virtual ~QuicStreamBase(void);

    /**
     * \brief Set the QUIC L5 object
     *
     * \param quicL5 a smart pointer to a QuicL5Protocol object
     */
    void SetQuicL5(Ptr<QuicL5Protocol> quicl5);

    /**
     * \brief Insert a frame in the TX buffer and trigger SendPendingData
     *
     * \param frame a smart pointer to a packer
     * \return -1 in case of errors, the size of the packet sent otherwise
     */
    int Send(Ptr<Packet> frame);

    /**
     * \brief Perform flow control by checking the available window
     *   according to what was negotiated with the other endpoint
     *   and the bytes in flight.
     * \warning This method handles differently stream 0 and the other streams.
     *
     * \return the available window for the transmission
     */
    uint32_t AvailableWindow() const;

    /**
     * \brief Compute the stream window for streams different from 0
     *
     * \return the amount of data that can be sent on the stream
     */
    uint32_t StreamWindow() const;

    /**
     * \brief Called by the QuicL5Protocol class to forward a frame for this stream
     *
     * \param frame a smart pointer for the received frame
     * \param sub the QuicSubheader of the received frame
     * \param address the Address of the sender
     * \return -1 in case of errors, 0 otherwise
     */
    int Recv(Ptr<Packet> frame, const QuicSubheader& subb, Address& address);

    /**
     * \brief Insert the frame in the buffer, or return -1 if the buffer is full
     *
     * \param frame a smart pointer to a packet
     * \return the size of the packet added to the frame, or -1 if the buffer is full
     */
    int AppendingTx(Ptr<Packet> frame);

    /**
     * \brief Check if there is data to send, and call SendDataFrame
     *
     * \return nFrameSent the number of frames sent in the stream
     */
    uint32_t SendPendingData(void);

    /**
     * \brief Resume sending if data is pending (after a flow-control window update)
     */
    void WakeUp(void);

    /**
     * \brief Abruptly terminate the sending side (RFC 9000 s3.1): drop unsent data and send
     * RESET_STREAM
     * \param errorCode application error code
     * \return true if a RESET_STREAM was generated
     */
    bool Reset(uint16_t errorCode);

    /**
     * \\brief Finish the sending side gracefully: the last byte is sent with the FIN bit
     * \\return true if the FIN was queued
     */
    bool Finish(void);

    /**
     * \brief Ask the peer to stop sending on this stream (STOP_SENDING); later data is discarded
     * \param errorCode application error code
     * \return true if a STOP_SENDING was generated
     */
    bool StopSending(uint16_t errorCode);

    /**
     * \brief Whether the stream was reset by either side
     * \return true if reset
     */
    bool IsReset(void) const;

    /**
     * \brief Whether application data is still buffered in the stream
     * \return true if data is pending
     */
    bool HasPendingData(void) const;

    /**
     * \brief Send a data frame of size maxSize
     *
     * \param seq the sequence number in the buffer of the next packet to be sent
     * \param the size of the frame to be sent
     * \return the size of the frame sent
     */
    uint32_t SendDataFrame(SequenceNumber32 seq, uint32_t maxSize);

    /**
     * \brief Calculate the maximum amount of data that can be received by this stream
     *
     * \return a uint32_t with the maximum amount of data
     */
    uint32_t SendMaxStreamData();

    /**
     * \brief Set the initial receive window, advertised to the peer (msquic:
     * StreamRecvWindowDefault)
     * \param initialWindow initial window in bytes
     */
    void InitRecvWindow(uint32_t initialWindow);

    /**
     * \brief Account for in-order delivered bytes: advance the advertised limits (auto-tuning)
     */
    void OnDelivered();

    /**
     * \brief Absolute stream offset up to which the peer may send
     * \return the limit
     */
    uint64_t GetMaxAllowedRecvOffset() const;

    // void CommandFlow (uint8_t type);

    /**
     * \brief Set the maximum amount of data that can be sent in this stream
     *
     * \param maxStreamData a uint32_t with the maximum amount of data
     */
    void SetMaxStreamData(uint64_t maxStreamData);

    /**
     * \brief Get the maximum amount of data that can be sent in this stream
     *
     * \return a uint32_t with the maximum amount of data
     */
    uint64_t GetMaxStreamData() const;

    /**
     * \brief Set the stream TX buffer size.
     * \param size the buffer size (in bytes)
     */
    void SetStreamSndBufSize(uint32_t size);

    /**
     * \brief Get the stream TX buffer size.
     * \returns the buffer size (in bytes)
     */
    uint32_t GetStreamSndBufSize(void) const;

    /**
     * \brief Set the stream RX buffer size.
     * \param size the buffer size (in bytes)
     */
    void SetStreamRcvBufSize(uint32_t size);

    /**
     * \brief Get the stream RX buffer size.
     * \returns the buffer size (in bytes)
     */
    uint32_t GetStreamRcvBufSize(void) const;

    // Implementation of QuicStream virtuals
    std::string StreamDirectionTypeToString() const;
    void SetStreamDirectionType(const QuicStreamDirectionTypes_t& streamDirectionType);
    QuicStreamDirectionTypes_t GetStreamDirectionType();
    void SetStreamType(const QuicStreamTypes_t& streamType);
    void SetStreamStateSendIf(bool condition, const QuicStreamStates_t& streamState);
    void SetStreamStateSend(const QuicStreamStates_t& streamState);
    void SetStreamStateRecv(const QuicStreamStates_t& streamState);
    void SetStreamStateRecvIf(bool condition, const QuicStreamStates_t& streamState);
    void SetNode(Ptr<Node> node);
    void SetConnectionId(uint64_t connId);
    void SetStreamId(uint64_t streamId);
    uint64_t GetStreamId(void);

    /** \\return true for the stream that carries the handshake, not an application stream */
    bool IsHandshake(void) const
    {
        return m_streamId == HANDSHAKE_STREAM_ID;
    }

    uint32_t GetStreamTxAvailable(void) const;

  protected:
    /**
     * \brief Make sure the receive buffer can hold a receive window of this size
     *
     * Out-of-order data can fill up to one window of the buffer, so the buffer is never smaller
     * than the window advertised to the peer (msquic sizes its receive buffer after the window in
     * the same way).
     * \param window the receive window in bytes
     */
    void GrowRxBuffer(uint32_t window);

    QuicStreamTypes_t m_streamType;                   //!< The stream type
    QuicStreamDirectionTypes_t m_streamDirectionType; //!< The stream direction
    QuicStreamStates_t m_streamStateSend;             //!< The state of the send stream
    QuicStreamStates_t m_streamStateRecv;             //!< The state of the receive stream
    Ptr<Node> m_node;                                 //!< The node this stream is associated with
    uint64_t m_connectionId;                          //!< The connection ID
    uint64_t m_streamId;                              //!< The stream ID
    Ptr<QuicL5Protocol> m_quicl5; //!< The L5 Protocol this stack is associated with

    // Flow Control Parameters
    uint64_t m_maxStreamData;        //!< Peer limit: highest stream offset we may send (absolute)
    uint64_t m_maxAllowedRecvOffset; //!< Highest stream offset we allow the peer to send (absolute)
    uint32_t m_recvWindow;           //!< Current receive window, grown by auto-tuning
    uint32_t m_recvWindowMax;        //!< Upper bound of the auto-tuned receive window
    uint64_t m_windowBytesDelivered{0}; //!< Bytes delivered since the last window update
    uint64_t m_windowBase{0}; //!< Delivered offset already accounted in m_windowBytesDelivered
    Time m_lastWindowUpdate;  //!< Last time MAX_STREAM_DATA was advanced
    TracedCallback<uint64_t, uint16_t, bool>
        m_streamResetTrace;       //!< Reset trace (id, error, by peer)
    bool m_finQueued{false};      //!< The application finished the sending side
    bool m_closedReported{false}; //!< The stream layer was told this stream is complete
    void CheckClosed(void);
    bool m_stopSendingSent{false}; //!< STOP_SENDING already sent on this stream
    uint64_t m_blockedReportedAt{
        UINT64_MAX};                 //!< Stream limit for which STREAM_DATA_BLOCKED was last sent
    uint64_t m_highestRecvOffset{0}; //!< Highest end offset received (connection-level accounting)
    uint64_t m_deliveredReported; //!< Bytes already reported to the connection-level flow control
    uint32_t m_maxAdvertisedData; //!< Last advertised MaxData
    uint32_t m_maxDataInterval;   //!< Interval between MaxData frames
    uint64_t m_sentSize;          //!< Amount of data sent in this stream
    uint64_t m_recvSize;          //!< Amount of data received in this stream
    bool m_fin; //!< A flag indicating if the FIN bit has already been received/sent
    Ptr<QuicStreamRxBuffer> m_rxBuffer;   //!< Rx buffer (reordering buffer)
    Ptr<QuicStreamTxBuffer> m_txBuffer;   //!< Tx buffer
    uint32_t m_streamTxBufferSize;        //!< Size of the stream TX buffer
    uint32_t m_streamRxBufferSize;        //!< Size of the stream RX buffer
    EventId m_streamSendPendingDataEvent; //!< Micro-delay event to send pending data
};

} // namespace ns3
#endif /* QUIC_STREAM_BASE_H_ */
