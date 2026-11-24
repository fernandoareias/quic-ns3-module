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
/*
#define NS_LOG_APPEND_CONTEXT \
  if (m_node and m_connectionId and (m_streamId >= 0)) { std::clog << " [node " << m_node->GetId ()
<< " socket " << m_connectionId << " stream " << m_streamId << " " << StreamDirectionTypeToString ()
<< "] "; }
*/

#include "quic-stream-base.h"

#include "quic-header.h"
#include "quic-stream-id-tag.h"
#include "quic-transport-parameters.h"

#include "ns3/abort.h"
#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/pointer.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicStreamBase");

NS_OBJECT_ENSURE_REGISTERED(QuicStreamBase);

TypeId
QuicStreamBase::GetTypeId(void)
{
    static TypeId tid =
        TypeId("ns3::QuicStreamBase")
            .SetParent<QuicStream>()
            .SetGroupName("Internet")
            .AddConstructor<QuicStreamBase>()
            .AddAttribute("StreamSndBufSize",
                          "QuicStreamBase maximum transmit buffer size (bytes)",
                          UintegerValue(4194304), // 4 MiB
                          MakeUintegerAccessor(&QuicStreamBase::m_streamTxBufferSize),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("StreamRcvBufSize",
                          "QuicStreamBase receive buffer size (bytes); it grows to hold the "
                          "receive window the stream advertises",
                          UintegerValue(4194304), // 4 MiB
                          MakeUintegerAccessor(&QuicStreamBase::m_streamRxBufferSize),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("StreamRecvWindowMax",
                          "The stream receive window stops doubling once it reaches this size "
                          "(msquic: the connection flow control window)",
                          UintegerValue(16777216),
                          MakeUintegerAccessor(&QuicStreamBase::m_recvWindowMax),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("MaxDataInterval",
                          "Interval between MAX_DATA frames",
                          UintegerValue(15000), // 10 packets
                          MakeUintegerAccessor(&QuicStreamBase::m_maxDataInterval),
                          MakeUintegerChecker<uint32_t>())
            .AddTraceSource("StreamReset",
                            "A stream was reset: (stream id, error code, by peer)",
                            MakeTraceSourceAccessor(&QuicStreamBase::m_streamResetTrace),
                            "ns3::QuicStreamBase::StreamResetTracedCallback");
    return tid;
}

QuicStreamBase::QuicStreamBase(void)
    : QuicStream(),
      m_streamType(NONE),
      m_streamDirectionType(UNKNOWN),
      m_streamStateSend(IDLE),
      m_streamStateRecv(IDLE),
      m_node(0),
      m_connectionId(0),
      m_streamId(0),
      m_quicl5(0),
      m_maxStreamData(0),
      m_maxAllowedRecvOffset(0),
      m_recvWindow(0),
      m_recvWindowMax(6291456),
      m_lastWindowUpdate(Seconds(0)),
      m_deliveredReported(0),
      m_maxAdvertisedData(0),
      m_sentSize(0),
      m_recvSize(0),
      m_fin(false)
{
    NS_LOG_FUNCTION(this);
    m_rxBuffer = CreateObject<QuicStreamRxBuffer>();
    m_txBuffer = CreateObject<QuicStreamTxBuffer>();
}

QuicStreamBase::~QuicStreamBase(void)
{
    NS_LOG_FUNCTION(this);
}

void
QuicStreamBase::SetQuicL5(Ptr<QuicL5Protocol> quicl5)
{
    NS_LOG_FUNCTION(this);
    m_quicl5 = quicl5;
    SetStreamRcvBufSize(m_streamRxBufferSize);
    SetStreamSndBufSize(m_streamTxBufferSize);
}

int
QuicStreamBase::Send(Ptr<Packet> frame)
{
    NS_LOG_FUNCTION(this);

    SetStreamStateSendIf(m_streamStateSend == IDLE and (m_streamDirectionType == SENDER or
                                                        m_streamDirectionType == BIDIRECTIONAL),
                         OPEN);

    if (m_streamStateSend == OPEN or m_streamStateSend == SEND)
    {
        int sent = AppendingTx(frame);
        if (sent >= 0 && !IsHandshake())
        {
            m_quicl5->NotifyStreamBacklog(m_streamId, true);
        }

        NS_LOG_LOGIC("Sending packets in stream. TxBufSize = "
                     << m_txBuffer->AppSize() << " AvailableWindow = " << AvailableWindow()
                     << " state " << QuicStreamStateName[m_streamStateSend]);

        if ((m_streamStateSend == OPEN or m_streamStateSend == SEND) and AvailableWindow() > 0)
        {
            if (!m_streamSendPendingDataEvent.IsPending())
            {
                m_streamSendPendingDataEvent =
                    Simulator::Schedule(TimeStep(1), &QuicStreamBase::SendPendingData, this);
            }
        }
        return sent;
    }
    else if (m_streamStateSend == RESET_SENT or m_streamStateSend == RESET_RECVD)
    {
        NS_LOG_WARN("Write on a reset stream discarded");
        return -1;
    }
    else
    {
        NS_ABORT_MSG("Sending in state" << QuicStreamStateName[m_streamStateSend]);
        // m_errno = ERROR_NOTCONN;
        return -1;
    }
}

int
QuicStreamBase::AppendingTx(Ptr<Packet> frame)
{
    NS_LOG_FUNCTION(this);

    if (!m_txBuffer->Add(frame))
    {
        NS_LOG_WARN("Exceeding Stream Tx Buffer Size");
        // m_quicl5->SignalAbortConnection
        // (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
        //                                      "Received RST_STREAM in Stream 0");
        // m_errno = ERROR_MSGSIZE;
        return -1;
    }
    return frame->GetSize();
}

uint32_t
QuicStreamBase::GetStreamTxAvailable() const
{
    return m_txBuffer->Available();
}

uint32_t
QuicStreamBase::SendPendingData(void)
{
    NS_LOG_FUNCTION(this);

    if (m_txBuffer->AppSize() == 0)
    {
        NS_LOG_INFO("Nothing to send");
        if (!IsHandshake())
        {
            m_quicl5->NotifyStreamBacklog(m_streamId, false);
        }
        return false;
    }

    uint32_t nFrameSent = 0;
    uint32_t availableWindow = AvailableWindow();

    while (availableWindow > 0 and m_txBuffer->AppSize() > 0)
    {
        //	  uint32_t availableData = m_txBuffer->Available();

        //	  if(availableData < availableWindow)
        //	  {
        //	          NS_LOG_INFO("Ask the app for more data before trying to send");
        //		  NotifySend(GetTxAvailable());
        //	  }

        //	  if(availableWindow < m_quicl5->GetMaxPacketSize() and availableData > availableWindow)
        //	  {
        //	          NS_LOG_INFO("Preventing Silly Windows Syndrome. Wait to Send.");
        //		  break;
        //	  }

        uint32_t s = std::min(availableWindow, (uint32_t)m_quicl5->GetMaxPacketSize());

        NS_LOG_DEBUG("BEFOREAvailable Window "
                     << AvailableWindow() << "Stream RWnd " << StreamWindow() << "BytesInFlight "
                     << m_txBuffer->BytesInFlight() << "BufferedSize " << m_txBuffer->AppSize()
                     << "MaxPacketSize " << (uint32_t)m_quicl5->GetMaxPacketSize());

        int success = SendDataFrame((SequenceNumber32)m_sentSize, s);

        availableWindow = AvailableWindow();

        if (success < 0)
        {
            return -1;
        }

        NS_LOG_DEBUG("AFTERAvailable Window "
                     << AvailableWindow() << "Stream RWnd " << StreamWindow() << "BytesInFlight "
                     << m_txBuffer->BytesInFlight() << "BufferedSize " << m_txBuffer->AppSize()
                     << "MaxPacketSize " << (uint32_t)m_quicl5->GetMaxPacketSize());

        ++nFrameSent;
    }

    if (m_txBuffer->AppSize() > 0 && !IsHandshake())
    {
        // RFC 9000 s4.1: tell the peer when flow control, not congestion control, stops us
        if (m_sentSize >= m_maxStreamData && m_blockedReportedAt != m_maxStreamData)
        {
            m_blockedReportedAt = m_maxStreamData;
            Ptr<Packet> p = Create<Packet>(0);
            p->AddHeader(QuicSubheader::CreateStreamBlocked(m_streamId, m_maxStreamData));
            m_quicl5->Send(p);
        }
        else if (m_sentSize < m_maxStreamData)
        {
            m_quicl5->ReportConnectionBlockedIfNeeded();
        }
    }

    if (!IsHandshake() && m_txBuffer->AppSize() == 0)
    {
        m_quicl5->NotifyStreamBacklog(m_streamId, false);
    }

    if (nFrameSent > 0)
    {
        NS_LOG_INFO("SendPendingData sent " << nFrameSent << " frames");
    }
    else
    {
        NS_LOG_INFO("SendPendingData no frames sent");
    }

    return nFrameSent;
}

uint32_t
QuicStreamBase::SendDataFrame(SequenceNumber32 seq, uint32_t maxSize)
{
    NS_LOG_FUNCTION(this);

    if (m_streamStateSend == OPEN and
        (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
    {
        SetStreamStateSend(SEND);
    }

    Ptr<Packet> frame = m_txBuffer->NextSequence(maxSize, seq);

    bool lengthBit = true;

    // the FIN goes with the last bytes of a stream the application finished
    bool finBit = m_finQueued && m_txBuffer->AppSize() == 0;
    QuicSubheader sub = QuicSubheader::CreateStreamSubHeader(m_streamId,
                                                             (uint64_t)seq.GetValue(),
                                                             frame->GetSize(),
                                                             m_sentSize != 0,
                                                             lengthBit,
                                                             finBit);
    m_sentSize += frame->GetSize();
    uint32_t dataSize = frame->GetSize();
    if (!IsHandshake())
    {
        m_quicl5->OnNewDataSent(dataSize);
    }

    frame->AddHeader(sub);
    int size = m_quicl5->Send(frame);
    if (size < 0)
    {
        frame->RemoveHeader(sub);
        m_txBuffer->Rejected(frame);
        NS_LOG_WARN("Sending error - could not append packet to socket buffer. Putting packet back "
                    "in stream buffer");
        m_quicl5
            ->NotifySocketTxFull(); // the socket wakes the stream again when it has sent packets
        m_sentSize -= frame->GetSize();
        if (!IsHandshake())
        {
            m_quicl5->OnNewDataSent(-(int64_t)dataSize);
        }
    }
    else if (m_streamStateSend == SEND and finBit and
             (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
    {
        SetStreamStateSend(DATA_SENT);
    }

    return size;
}

uint32_t
QuicStreamBase::AvailableWindow() const
{
    NS_LOG_FUNCTION(this);
    uint32_t streamRWnd = (!IsHandshake()) ? StreamWindow() : UINT32_MAX;
    return streamRWnd;
}

uint32_t
QuicStreamBase::StreamWindow() const
{
    NS_LOG_FUNCTION(this);
    uint64_t streamWin = (m_maxStreamData > m_sentSize) ? m_maxStreamData - m_sentSize : 0;
    uint64_t connWin = (!IsHandshake()) ? m_quicl5->ConnectionSendWindow() : UINT64_MAX;
    return (uint32_t)std::min<uint64_t>(std::min(streamWin, connWin), UINT32_MAX);
}

int
QuicStreamBase::Recv(Ptr<Packet> frame, const QuicSubheader& sub, Address& address)
{
    NS_LOG_FUNCTION(this);

    uint8_t frameType = sub.GetFrameType();

    switch (frameType)
    {
    case QuicSubheader::RESET_STREAM:
        if (IsHandshake())
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received RST_STREAM in Stream 0");
            return -1;
        }

        if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received RST_STREAM in send-only Stream");
            return -1;
        }

        if ((m_streamStateRecv == DATA_READ or m_streamStateRecv == RESET_READ))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Receiving RST_STREAM Frames in DATA_READ or RESET_READ Stream State");
            return -1;
        }

        if (m_fin and m_rxBuffer->GetFinalSize() != sub.GetOffset())
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::FINAL_SIZE_ERROR,
                "RST_STREAM causes final offset to change for a Stream");
            return -1;
        }

        if (m_streamStateRecv == RESET_RECVD)
        {
            break; // duplicate (retransmission)
        }

        if (sub.GetOffset() < m_highestRecvOffset)
        {
            m_quicl5->SignalAbortConnection(QuicSubheader::TransportErrorCodes_t::FINAL_SIZE_ERROR,
                                            "RESET_STREAM final size below data already received");
            return -1;
        }
        if (sub.GetOffset() > m_maxAllowedRecvOffset)
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                "RESET_STREAM final size above Max Stream Data limit");
            return -1;
        }

        // The final size counts against connection flow control even though the data is never
        // delivered: account for it and give the credit back (RFC 9000 s4.5)
        if (sub.GetOffset() > m_highestRecvOffset)
        {
            uint64_t delta = sub.GetOffset() - m_highestRecvOffset;
            m_highestRecvOffset = sub.GetOffset();
            if (!m_quicl5->OnBytesReceivedAtOffset(delta))
            {
                m_quicl5->SignalAbortConnection(
                    QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                    "Received more data w.r.t. Max Data limit");
                return -1;
            }
        }
        if (sub.GetOffset() > m_deliveredReported)
        {
            m_quicl5->OnBytesDelivered(sub.GetOffset() - m_deliveredReported);
            m_deliveredReported = sub.GetOffset();
        }

        SetStreamStateRecv(RESET_RECVD);
        m_rxBuffer = CreateObject<QuicStreamRxBuffer>();
        m_rxBuffer->SetMaxBufferSize(GetStreamRcvBufSize());
        NS_LOG_INFO("Stream " << m_streamId << " reset by peer, error " << sub.GetErrorCode());
        m_streamResetTrace(m_streamId, sub.GetErrorCode(), true);
        SetStreamStateRecv(RESET_READ);
        CheckClosed();

        break;

    case QuicSubheader::MAX_STREAM_DATA:
        if (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received MAX_STREAM_DATA in receive-only Stream");
            return -1;
        }
        else
        {
            SetMaxStreamData(sub.GetMaxStreamData());
            NS_LOG_INFO("Max stream data (flow control) - " << m_maxStreamData);
        }

        break;

    case QuicSubheader::STREAM_DATA_BLOCKED:
        if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received STREAM_BLOCKED in send-only Stream");
            return -1;
        }
        if (!IsHandshake())
        {
            // The peer may have missed our last credit: repeat it
            QuicSubheader msd =
                QuicSubheader::CreateMaxStreamData(m_streamId, m_maxAllowedRecvOffset);
            Ptr<Packet> p = Create<Packet>(0);
            p->AddHeader(msd);
            m_quicl5->Send(p);
        }

        break;

    case QuicSubheader::STOP_SENDING:
        if (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received STOP_SENDING in receive-only Stream");
            return -1;
        }

        // RFC 9000 s3.5: respond with RESET_STREAM using the requested error code
        Reset(sub.GetErrorCode());

        break;

    case QuicSubheader::STREAM:
    case QuicSubheader::STREAM_FIN:
    case QuicSubheader::STREAM_LEN:
    case QuicSubheader::STREAM_LEN_FIN:
    case QuicSubheader::STREAM_OFF:
    case QuicSubheader::STREAM_OFF_FIN:
    case QuicSubheader::STREAM_OFF_LEN:
    case QuicSubheader::STREAM_OFF_LEN_FIN: {
        if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received STREAM in send-only Stream");
            return -1;
        }

        if (m_streamStateRecv == RESET_RECVD or m_streamStateRecv == RESET_READ)
        {
            NS_LOG_INFO("Discarding STREAM frame on a reset stream");
            break;
        }

        if (!(m_streamStateRecv == IDLE or m_streamStateRecv == RECV or
              m_streamStateRecv == SIZE_KNOWN))
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received STREAM in State unequal to IDLE, RECV, SIZE_KNOWN");
            return -1;
        }

        if (!IsHandshake() &&
            sub.GetOffset() + std::max<uint64_t>(sub.GetLength(), frame->GetSize()) >
                m_maxAllowedRecvOffset)
        {
            NS_LOG_WARN("stream " << m_streamId << " received up to "
                                  << sub.GetOffset() +
                                         std::max<uint64_t>(sub.GetLength(), frame->GetSize())
                                  << " but the advertised limit is " << m_maxAllowedRecvOffset);
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                "Received more data w.r.t. Max Stream Data limit");
            return -1;
        }

        if (!IsHandshake())
        {
            uint64_t endOffset =
                sub.GetOffset() + std::max<uint64_t>(sub.GetLength(), frame->GetSize());
            if (endOffset > m_highestRecvOffset)
            {
                uint64_t delta = endOffset - m_highestRecvOffset;
                m_highestRecvOffset = endOffset;
                if (!m_quicl5->OnBytesReceivedAtOffset(delta))
                {
                    m_quicl5->SignalAbortConnection(
                        QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                        "Received more data w.r.t. Max Data limit");
                    return -1;
                }
            }
        }

        SetStreamStateRecvIf(m_streamStateRecv == IDLE, RECV);

        if (m_quicl5->ContainsTransportParameters() and IsHandshake())
        {
            QuicTransportParameters transport;
            frame->RemoveHeader(transport);
            m_quicl5->OnReceivedTransportParameters(transport);
        }

        if (m_fin and sub.IsStreamFin() and m_rxBuffer->GetFinalSize() != sub.GetOffset())
        {
            m_quicl5->SignalAbortConnection(QuicSubheader::TransportErrorCodes_t::FINAL_SIZE_ERROR,
                                            "STREAM causes final offset to change for a Stream");
            return -1;
        }

        m_fin = sub.IsStreamFin();

        if (m_fin && IsHandshake())
        {
            m_quicl5->SignalAbortConnection(
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "Received Stream FIN in Stream 0");
            return -1;
        }

        SetStreamStateRecvIf(m_streamStateRecv == RECV and m_fin, SIZE_KNOWN);

        // Retransmissions may be re-segmented by the sender, so a frame can overlap data
        // already delivered (RFC 9000 s2.2, s13.3): drop or trim the delivered prefix.
        uint64_t frameOffset = sub.GetOffset();
        uint64_t frameLen = (!IsHandshake()) ? frame->GetSize() : sub.GetLength();
        bool staleFrame = false;
        if (!IsHandshake() && frameLen > 0 && frameOffset < m_recvSize)
        {
            if (frameOffset + frameLen <= m_recvSize)
            {
                staleFrame = true;
            }
            else
            {
                frame->RemoveAtStart(m_recvSize - frameOffset);
                frameLen = frame->GetSize();
                frameOffset = m_recvSize;
            }
        }

        if (staleFrame)
        {
            NS_LOG_INFO("Discarding stale frame - offset " << sub.GetOffset() << " < "
                                                           << m_recvSize);
        }
        else if (m_recvSize == frameOffset)
        {
            NS_LOG_INFO("Received a frame with the correct order of size " << frameLen);
            m_recvSize += frameLen;

            NS_LOG_LOGIC("Try to Flush RxBuffer if Available - offset " << m_recvSize);
            // check if the packets in the RX buffer can be released (in order release)
            Ptr<Packet> payload = m_rxBuffer->ExtractInOrder(m_recvSize);
            if (payload != nullptr && payload->GetSize() > 0)
            {
                NS_LOG_LOGIC("Extracting " << payload->GetSize() << " bytes from RxBuffer");
                m_recvSize += payload->GetSize();
                frame->AddAtEnd(payload);
            }
            NS_LOG_LOGIC("Flushed RxBuffer - new offset "
                         << m_recvSize << ", " << m_rxBuffer->Available() << "bytes available");

            SetStreamStateRecvIf(m_streamStateRecv == SIZE_KNOWN and m_rxBuffer->Size() == 0,
                                 DATA_RECVD);
            OnDelivered();

            if (!IsHandshake())
            {
                if (frame->GetSize() > 0)
                {
                    frame->AddByteTag(QuicStreamIdTag(m_streamId), 0, frame->GetSize());
                    m_quicl5->Recv(frame, address);
                }
            }
            else
            {
                NS_LOG_INFO("Received handshake Message in Stream 0");
            }

            SetStreamStateRecvIf(m_streamStateRecv == DATA_RECVD, DATA_READ);
            CheckClosed();
        }
        else
        {
            NS_LOG_INFO("Buffering unordered received frame - offset "
                        << m_recvSize << ", frame offset " << frameOffset);
            QuicSubheader bufSub = sub;
            bufSub.SetOffset(frameOffset);
            if (!m_rxBuffer->Add(frame, bufSub) && frame->GetSize() > 0)
            {
                // Insert failed: No or duplicate data, or RX buffer full
                NS_LOG_WARN("Dropping packet as it could not be inserted in RX buffer");
                if (frame->GetSize() > m_rxBuffer->Available())
                {
                    // Abort connection if indeed buffer is full
                    m_quicl5->SignalAbortConnection(QuicSubheader::TransportErrorCodes_t::NO_ERROR,
                                                    "Aborting connection due to full RX buffer");
                }
            }
        }

        break;
    }

    default:

        NS_ABORT_MSG("Received Corrupted Frame");
        break;
    }

    return 0;
}

uint32_t
QuicStreamBase::SendMaxStreamData()
{
    return m_recvSize + m_rxBuffer->Available();
}

void
QuicStreamBase::SetMaxStreamData(uint64_t maxStreamData)
{
    NS_LOG_FUNCTION(this << maxStreamData);
    if (maxStreamData <= m_maxStreamData)
    {
        return;
    }
    m_maxStreamData = maxStreamData;
    if (m_txBuffer->AppSize() > 0 && !m_streamSendPendingDataEvent.IsPending())
    {
        m_streamSendPendingDataEvent =
            Simulator::Schedule(TimeStep(1), &QuicStreamBase::SendPendingData, this);
    }
}

bool
QuicStreamBase::Finish(void)
{
    NS_LOG_FUNCTION(this);
    if (IsHandshake() || m_finQueued ||
        !(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL) ||
        m_streamStateSend == RESET_SENT || m_streamStateSend == RESET_RECVD ||
        m_streamStateSend == DATA_SENT || m_streamStateSend == DATA_RECVD)
    {
        return false;
    }
    SetStreamStateSendIf(m_streamStateSend == IDLE, OPEN);
    m_finQueued = true;
    if (m_txBuffer->AppSize() == 0)
    {
        // nothing left to carry the FIN: send it alone, at the final offset
        QuicSubheader sub = QuicSubheader::CreateStreamSubHeader(m_streamId,
                                                                 m_sentSize,
                                                                 0,
                                                                 m_sentSize != 0,
                                                                 true,
                                                                 true);
        Ptr<Packet> frame = Create<Packet>(0);
        frame->AddHeader(sub);
        m_quicl5->Send(frame);
        SetStreamStateSend(DATA_SENT);
    }
    else
    {
        WakeUp();
    }
    return true;
}

void
QuicStreamBase::CheckClosed(void)
{
    if (m_closedReported || IsHandshake())
    {
        return;
    }
    bool recvDone = m_streamDirectionType == SENDER || m_streamStateRecv == DATA_READ ||
                    m_streamStateRecv == RESET_READ;
    bool sendDone = m_streamDirectionType == RECEIVER || m_streamStateSend == IDLE ||
                    m_streamStateSend == DATA_SENT || m_streamStateSend == DATA_RECVD ||
                    m_streamStateSend == RESET_SENT || m_streamStateSend == RESET_RECVD;
    if (recvDone && sendDone)
    {
        m_closedReported = true;
        m_quicl5->OnStreamClosed(this);
    }
}

bool
QuicStreamBase::Reset(uint16_t errorCode)
{
    NS_LOG_FUNCTION(this << errorCode);
    if (IsHandshake() ||
        !(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL) ||
        m_streamStateSend == RESET_SENT || m_streamStateSend == RESET_RECVD ||
        m_streamStateSend == DATA_RECVD)
    {
        return false;
    }

    m_txBuffer->DiscardAppData();
    m_quicl5->NotifyStreamBacklog(m_streamId, false);
    if (m_streamSendPendingDataEvent.IsPending())
    {
        m_streamSendPendingDataEvent.Cancel();
    }

    Ptr<Packet> p = Create<Packet>(0);
    p->AddHeader(QuicSubheader::CreateRstStream(m_streamId, errorCode, m_sentSize));
    m_quicl5->Send(p);
    SetStreamStateSend(RESET_SENT);
    m_streamResetTrace(m_streamId, errorCode, false);
    return true;
}

bool
QuicStreamBase::StopSending(uint16_t errorCode)
{
    NS_LOG_FUNCTION(this << errorCode);
    if (IsHandshake() ||
        !(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL) ||
        m_stopSendingSent || m_streamStateRecv == DATA_RECVD || m_streamStateRecv == DATA_READ ||
        m_streamStateRecv == RESET_RECVD || m_streamStateRecv == RESET_READ)
    {
        return false;
    }
    m_stopSendingSent = true;
    Ptr<Packet> p = Create<Packet>(0);
    p->AddHeader(QuicSubheader::CreateStopSending(m_streamId, errorCode));
    m_quicl5->Send(p);
    return true;
}

bool
QuicStreamBase::IsReset(void) const
{
    return m_streamStateSend == RESET_SENT or m_streamStateSend == RESET_RECVD or
           m_streamStateRecv == RESET_RECVD or m_streamStateRecv == RESET_READ;
}

bool
QuicStreamBase::HasPendingData(void) const
{
    return m_txBuffer->AppSize() > 0;
}

void
QuicStreamBase::WakeUp(void)
{
    if (m_txBuffer->AppSize() > 0 && !m_streamSendPendingDataEvent.IsPending())
    {
        m_streamSendPendingDataEvent =
            Simulator::Schedule(TimeStep(1), &QuicStreamBase::SendPendingData, this);
    }
}

void
QuicStreamBase::InitRecvWindow(uint32_t initialWindow)
{
    m_recvWindow = initialWindow;
    m_maxAllowedRecvOffset = (IsHandshake()) ? UINT64_MAX : initialWindow;
    m_lastWindowUpdate = Simulator::Now();
    if (!IsHandshake())
    {
        GrowRxBuffer(m_recvWindow);
    }
}

void
QuicStreamBase::GrowRxBuffer(uint32_t window)
{
    if (m_rxBuffer->GetMaxBufferSize() < window)
    {
        m_rxBuffer->SetMaxBufferSize(window);
    }
}

uint64_t
QuicStreamBase::GetMaxAllowedRecvOffset() const
{
    return m_maxAllowedRecvOffset;
}

void
QuicStreamBase::OnDelivered()
{
    if (m_recvSize > m_deliveredReported)
    {
        m_quicl5->OnBytesDelivered(m_recvSize - m_deliveredReported);
        m_deliveredReported = m_recvSize;
    }
    if (IsHandshake() || m_recvWindow == 0)
    {
        return;
    }
    // msquic QuicStreamOnBytesDelivered: a window update is due once 1/4 of the window was
    // consumed; the window doubles when that happens within about one RTT (up to the connection
    // window). Without it, the credit is still advanced when an ACK is about to be sent anyway.
    Time now = Simulator::Now();
    m_windowBytesDelivered += m_recvSize - m_windowBase;
    m_windowBase = m_recvSize;
    uint64_t threshold = std::max<uint64_t>(m_recvWindow / 4, 1);
    if (m_windowBytesDelivered >= threshold)
    {
        Time srtt = m_quicl5->GetSmoothedRtt();
        if (m_recvWindow < m_recvWindowMax && srtt > Seconds(0))
        {
            Time timeThreshold = Time(srtt.GetTimeStep() *
                                      (int64_t)(m_windowBytesDelivered * 1000 / threshold) / 1000);
            if (now - m_lastWindowUpdate <= timeThreshold)
            {
                m_recvWindow = (uint32_t)std::min<uint64_t>((uint64_t)m_recvWindow * 2, UINT32_MAX);
                GrowRxBuffer(m_recvWindow);
            }
        }
        m_lastWindowUpdate = now;
        m_windowBytesDelivered = 0;
    }
    else
    {
        // msquic also advances the credit when an ACK is about to go out, because it rides in the
        // same packet. Here a window update is a packet of its own, so it waits for the threshold.
        return;
    }
    uint64_t newMax = m_recvSize + m_recvWindow;
    if (newMax <= m_maxAllowedRecvOffset)
    {
        return;
    }
    m_maxAllowedRecvOffset = newMax;
    QuicSubheader msd = QuicSubheader::CreateMaxStreamData(m_streamId, m_maxAllowedRecvOffset);
    Ptr<Packet> p = Create<Packet>(0);
    p->AddHeader(msd);
    m_quicl5->Send(p);
}

uint64_t
QuicStreamBase::GetMaxStreamData() const
{
    return m_maxStreamData;
}

void
QuicStreamBase::SetStreamDirectionType(const QuicStreamDirectionTypes_t& streamDirectionType)
{
    NS_LOG_FUNCTION(this);
    m_streamDirectionType = streamDirectionType;
}

QuicStream::QuicStreamDirectionTypes_t
QuicStreamBase::GetStreamDirectionType()
{
    return m_streamDirectionType;
}

void
QuicStreamBase::SetStreamType(const QuicStreamTypes_t& streamType)
{
    NS_LOG_FUNCTION(this);
    m_streamType = streamType;
}

void
QuicStreamBase::SetStreamStateSend(const QuicStreamStates_t& streamState)
{
    NS_LOG_FUNCTION(this);

    if (m_streamType == SERVER_INITIATED_BIDIRECTIONAL or
        m_streamType == SERVER_INITIATED_UNIDIRECTIONAL)
    {
        NS_LOG_INFO("Server Stream " << QuicStreamStateName[m_streamStateSend] << " -> "
                                     << QuicStreamStateName[streamState] << "");
    }
    else
    {
        NS_LOG_INFO("Client Stream " << QuicStreamStateName[m_streamStateSend] << " -> "
                                     << QuicStreamStateName[streamState] << "");
    }

    m_streamStateSend = streamState;
}

void
QuicStreamBase::SetStreamStateSendIf(bool condition, const QuicStreamStates_t& streamState)
{
    NS_LOG_FUNCTION(this);
    if (condition)
    {
        SetStreamStateSend(streamState);
    }
}

void
QuicStreamBase::SetStreamStateRecv(const QuicStreamStates_t& streamState)
{
    NS_LOG_FUNCTION(this);

    if (m_streamType == SERVER_INITIATED_BIDIRECTIONAL or
        m_streamType == SERVER_INITIATED_UNIDIRECTIONAL)
    {
        NS_LOG_INFO("Server Stream " << QuicStreamStateName[m_streamStateRecv] << " -> "
                                     << QuicStreamStateName[streamState] << "");
    }
    else
    {
        NS_LOG_INFO("Client Stream " << QuicStreamStateName[m_streamStateRecv] << " -> "
                                     << QuicStreamStateName[streamState] << "");
    }

    m_streamStateRecv = streamState;
}

void
QuicStreamBase::SetStreamStateRecvIf(bool condition, const QuicStreamStates_t& streamState)
{
    NS_LOG_FUNCTION(this);
    if (condition)
    {
        SetStreamStateRecv(streamState);
    }
}

void
QuicStreamBase::SetNode(Ptr<Node> node)
{
    NS_LOG_FUNCTION(this);
    m_node = node;
}

void
QuicStreamBase::SetStreamId(uint64_t streamId)
{
    NS_LOG_FUNCTION(this);
    m_streamId = streamId;
    if (streamId == HANDSHAKE_STREAM_ID)
    {
        SetStreamType(QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
        return;
    }

    uint64_t mask = 0x00000003;

    switch (m_streamId & mask)
    {
    case 0:
        SetStreamType(QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
        break;
    case 1:
        SetStreamType(QuicStream::SERVER_INITIATED_BIDIRECTIONAL);
        break;
    case 2:
        SetStreamType(QuicStream::CLIENT_INITIATED_UNIDIRECTIONAL);
        break;
    case 3:
        SetStreamType(QuicStream::SERVER_INITIATED_UNIDIRECTIONAL);
        break;
    }
}

uint64_t
QuicStreamBase::GetStreamId(void)
{
    return m_streamId;
}

void
QuicStreamBase::SetConnectionId(uint64_t connId)
{
    NS_LOG_FUNCTION(this << connId);
    m_connectionId = connId;
}

std::string
QuicStreamBase::StreamDirectionTypeToString() const
{
    static const char* StreamDirectionTypeNames[6] = {"SENDER",
                                                      "RECEIVER",
                                                      "BIDIRECTIONAL",
                                                      "UNKNOWN"};

    std::string typeDescription = "";

    typeDescription.append(StreamDirectionTypeNames[m_streamDirectionType]);

    return typeDescription;
}

void
QuicStreamBase::SetStreamSndBufSize(uint32_t size)
{
    NS_LOG_FUNCTION(this << size);
    m_streamTxBufferSize = size;
    m_txBuffer->SetMaxBufferSize(size);
}

uint32_t
QuicStreamBase::GetStreamSndBufSize(void) const
{
    return m_txBuffer->GetMaxBufferSize();
}

void
QuicStreamBase::SetStreamRcvBufSize(uint32_t size)
{
    NS_LOG_FUNCTION(this << size);
    m_streamRxBufferSize = size;
    m_rxBuffer->SetMaxBufferSize(size);
}

uint32_t
QuicStreamBase::GetStreamRcvBufSize(void) const
{
    return m_rxBuffer->GetMaxBufferSize();
}

} // namespace ns3
