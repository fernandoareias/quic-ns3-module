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

#include "quic-l5-protocol.h"

#include "quic-socket-base.h"
#include "quic-socket-factory.h"
#include "quic-stream-base.h"

#include "ns3/assert.h"
#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/object-vector.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicL5Protocol");

NS_OBJECT_ENSURE_REGISTERED(QuicL5Protocol);

// #undef NS_LOG_APPEND_CONTEXT
// #define NS_LOG_APPEND_CONTEXT
// if (m_node and m_connectionId) { std::clog << " [node " << m_node->GetId () << " socket " <<
// m_connectionId << "] "; }

TypeId
QuicL5Protocol::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicL5Protocol")
                            .SetParent<QuicSocketBase>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicL5Protocol>()
                            .AddAttribute("StreamList",
                                          "The list of streams associated to this protocol.",
                                          ObjectVectorValue(),
                                          MakeObjectVectorAccessor(&QuicL5Protocol::m_streams),
                                          MakeObjectVectorChecker<QuicStreamBase>());
    return tid;
}

QuicL5Protocol::QuicL5Protocol()
    : m_socket(0),
      m_node(0),
      m_connectionId()
{
    NS_LOG_FUNCTION_NOARGS();
    NS_LOG_LOGIC("Made a QuicL5Protocol " << this);
    m_socket = 0;
    m_node = 0;
    m_connectionId = QuicConnectionId();
}

QuicL5Protocol::~QuicL5Protocol()
{
    NS_LOG_FUNCTION(this);
}

bool
QuicL5Protocol::IsLocallyInitiated(uint64_t streamId) const
{
    bool serverInitiated = (streamId & 1) == 1;
    return serverInitiated == m_socket->IsServerSide();
}

Ptr<QuicStreamBase>
QuicL5Protocol::AddStream(uint64_t streamId)
{
    NS_LOG_FUNCTION(this << streamId);
    Ptr<QuicStreamBase> stream = CreateObject<QuicStreamBase>();
    stream->SetQuicL5(this);
    stream->SetNode(m_node);
    stream->SetConnectionId(m_connectionId);
    stream->SetStreamId(streamId);

    if (streamId == QuicStream::HANDSHAKE_STREAM_ID)
    {
        stream->SetStreamDirectionType(QuicStream::BIDIRECTIONAL);
        stream->SetMaxStreamData(UINT64_MAX);
        stream->InitRecvWindow(m_socket->GetOwnStreamRecvWindow(true, true));
    }
    else
    {
        bool local = IsLocallyInitiated(streamId);
        bool bidi = (streamId & 2) == 0;
        stream->SetStreamDirectionType(bidi ? QuicStream::BIDIRECTIONAL
                                            : (local ? QuicStream::SENDER : QuicStream::RECEIVER));
        stream->SetMaxStreamData(m_socket->GetPeerStreamDataLimit(local, bidi));
        stream->InitRecvWindow(m_socket->GetOwnStreamRecvWindow(local, bidi));
    }
    m_streams.push_back(stream);
    m_streamById[streamId] = stream;
    return stream;
}

void
QuicL5Protocol::CreateHandshakeStream(void)
{
    if (m_streamById.find(QuicStream::HANDSHAKE_STREAM_ID) == m_streamById.end())
    {
        AddStream(QuicStream::HANDSHAKE_STREAM_ID);
    }
}

Ptr<QuicStreamBase>
QuicL5Protocol::OpenLocalStream(uint64_t streamId)
{
    NS_LOG_FUNCTION(this << streamId);
    Ptr<QuicStreamBase> existing = SearchStream(streamId);
    if (existing != nullptr)
    {
        return existing;
    }
    if (!IsLocallyInitiated(streamId))
    {
        NS_LOG_WARN("Stream " << streamId << " belongs to the peer: it cannot be opened here");
        return nullptr;
    }
    bool bidi = (streamId & 2) == 0;
    uint64_t count = (streamId >> 2) + 1;
    // RFC 9000 s4.6: the peer's stream limit; tell it when that is what stops us
    if (count > m_socket->GetPeerMaxStreams(bidi))
    {
        NS_LOG_INFO("Stream limit reached (" << m_socket->GetPeerMaxStreams(bidi)
                                             << "), sending STREAMS_BLOCKED");
        m_socket->SendStreamsBlockedFrame(m_socket->GetPeerMaxStreams(bidi), bidi);
        return nullptr;
    }
    // RFC 9000 s3.2: using a stream id opens every lower numbered stream of the same type
    uint64_t type = streamId & 3;
    while (m_streamsCreated[type] < count)
    {
        AddStream(type + (m_streamsCreated[type] << 2));
        ++m_streamsCreated[type];
    }
    return SearchStream(streamId);
}

Ptr<QuicStreamBase>
QuicL5Protocol::GetStreamForPeer(uint64_t streamId, bool& fatal)
{
    fatal = false;
    Ptr<QuicStreamBase> stream = SearchStream(streamId);
    if (stream != nullptr)
    {
        return stream;
    }
    if (IsLocallyInitiated(streamId))
    {
        // a frame for a stream of ours that was never opened (RFC 9000 s19.8)
        SignalAbortConnection(QuicSubheader::TransportErrorCodes_t::STREAM_STATE_ERROR,
                              "Frame for a local stream that was not opened");
        fatal = true;
        return nullptr;
    }
    bool bidi = (streamId & 2) == 0;
    uint64_t count = (streamId >> 2) + 1;
    if (count > m_socket->GetOwnMaxStreams(bidi))
    {
        SignalAbortConnection(QuicSubheader::TransportErrorCodes_t::STREAM_LIMIT_ERROR,
                              "Peer used more streams than allowed");
        fatal = true;
        return nullptr;
    }
    uint64_t type = streamId & 3;
    while (m_streamsCreated[type] < count)
    {
        AddStream(type + (m_streamsCreated[type] << 2));
        ++m_streamsCreated[type];
    }
    return SearchStream(streamId);
}

void
QuicL5Protocol::OnStreamClosed(Ptr<QuicStreamBase> stream)
{
    if (stream->IsHandshake() || IsLocallyInitiated(stream->GetStreamId()))
    {
        return;
    }
    bool bidi = (stream->GetStreamId() & 2) == 0;
    m_socket->GrantPeerStream(bidi);
}

void
QuicL5Protocol::SetSocket(Ptr<QuicSocketBase> sock)
{
    NS_LOG_FUNCTION(this);
    m_socket = PeekPointer(sock);
}

int
QuicL5Protocol::DispatchSend(Ptr<Packet> data)
{
    // no stream given: use the first bidirectional stream this endpoint initiates (id 0 for a
    // client, 1 for a server), as an application using a single stream would
    return DispatchSend(data, m_socket->IsServerSide() ? 1 : 0);
}

int
QuicL5Protocol::DispatchSend(Ptr<Packet> data, uint64_t streamId)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_INFO("Send packet on (specified) stream " << streamId);

    Ptr<QuicStreamBase> stream = SearchStream(streamId);
    if (stream == nullptr)
    {
        if (streamId == QuicStream::HANDSHAKE_STREAM_ID)
        {
            CreateHandshakeStream();
            stream = SearchStream(streamId);
        }
        else
        {
            stream = OpenLocalStream(streamId);
        }
    }
    if (stream == nullptr)
    {
        return -1;
    }

    if (stream->GetStreamDirectionType() == QuicStream::SENDER or
        stream->GetStreamDirectionType() == QuicStream::BIDIRECTIONAL)
    {
        return stream->Send(data);
    }
    return -1;
}

int
QuicL5Protocol::DispatchRecv(Ptr<Packet> data, Address& address)
{
    NS_LOG_FUNCTION(this);
    m_frameError = 0;
    auto disgregated = DisgregateRecv(data);

    if (m_frameError != 0)
    {
        SignalAbortConnection(static_cast<QuicSubheader::TransportErrorCodes_t>(m_frameError),
                              "Malformed frame");
        return -1;
    }

    if (m_socket->CheckIfPacketOverflowMaxDataLimit(disgregated))
    {
        NS_LOG_WARN("Maximum data limit overflow");
        // put here this check instead of in QuicSocketBase due to framework mismatch in
        // packet->Copy()
        SignalAbortConnection(QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                              "Received more data w.r.t. Max Data limit");
        return -1;
    }

    bool onlyAckFrames = true;
    for (auto& elem : disgregated)
    {
        if (!elem.second.IsAck())
        {
            onlyAckFrames = false;
        }
        m_socket->NoteFrame(elem.second);
    }

    for (auto it = disgregated.begin(); it != disgregated.end(); ++it)
    {
        QuicSubheader sub = (*it).second;

        if (sub.IsRstStream() or sub.IsMaxStreamData() or sub.IsStreamBlocked() or
            sub.IsStopSending() or sub.IsStream())
        {
            Ptr<QuicStreamBase> stream;
            if (sub.GetStreamId() == QuicStream::HANDSHAKE_STREAM_ID)
            {
                CreateHandshakeStream();
                stream = SearchStream(QuicStream::HANDSHAKE_STREAM_ID);
            }
            else
            {
                bool fatal = false;
                stream = GetStreamForPeer(sub.GetStreamId(), fatal);
                if (fatal)
                {
                    return -1;
                }
            }

            // MAX_STREAM_DATA and STOP_SENDING travel from the receiving to the sending side
            bool towardsSender = sub.IsMaxStreamData() or sub.IsStopSending();
            if (stream != nullptr and
                (towardsSender or stream->GetStreamDirectionType() == QuicStream::RECEIVER or
                 stream->GetStreamDirectionType() == QuicStream::BIDIRECTIONAL))
            {
                NS_LOG_INFO("Receiving frame on stream " << stream->GetStreamId()
                                                         << " trigger stream");
                stream->Recv((*it).first, sub, address);
            }
        }
        else
        {
            NS_LOG_INFO("Receiving frame on stream " << sub.GetStreamId() << " trigger socket");
            m_socket->OnReceivedFrame(sub);
        }
    }

    // trigger ACK TX if the received packet was not ACK-only
    return !onlyAckFrames;
}

int
QuicL5Protocol::Send(Ptr<Packet> frame)
{
    NS_LOG_FUNCTION(this);

    return m_socket->AppendingTx(frame);
}

int
QuicL5Protocol::Recv(Ptr<Packet> frame, Address& address)
{
    NS_LOG_FUNCTION(this);

    m_socket->AppendingRx(frame, address);

    return frame->GetSize();
}

std::vector<Ptr<Packet>>
QuicL5Protocol::DisgregateSend(Ptr<Packet> data)
{
    NS_LOG_FUNCTION(this);

    uint32_t dataSizeByte = data->GetSize();
    std::vector<Ptr<Packet>> disgregated;
    // data->Print(std::cout);

    // Equally distribute load on all streams except on stream 0
    uint32_t loadPerStream = dataSizeByte / (m_streams.size() - 1);
    uint32_t remainingLoad = dataSizeByte - loadPerStream * (m_streams.size() - 1);
    if (loadPerStream < 1)
    {
        loadPerStream = 1;
    }

    for (uint32_t start = 0; start < dataSizeByte; start += loadPerStream)
    {
        if (remainingLoad > 0 && start + remainingLoad == dataSizeByte)
        {
            Ptr<Packet> remainingfragment = data->CreateFragment(start, remainingLoad);
            disgregated.push_back(remainingfragment);
        }
        else
        {
            Ptr<Packet> fragment = data->CreateFragment(start, loadPerStream);
            disgregated.push_back(fragment);
        }
    }

    return disgregated;
}

std::vector<std::pair<Ptr<Packet>, QuicSubheader>>
QuicL5Protocol::DisgregateRecv(Ptr<Packet> data)
{
    NS_LOG_FUNCTION(this);

    uint32_t dataSizeByte = data->GetSize();
    std::vector<std::pair<Ptr<Packet>, QuicSubheader>> disgregated;
    NS_LOG_INFO("DisgregateRecv for a packet with size " << dataSizeByte);
    // data->Print(std::cout);

    // the packet could contain multiple frames
    // each of them starts with a subheader
    // cycle through the data packet and extract the frames
    for (uint32_t start = 0; start < dataSizeByte;)
    {
        if (data->GetSize() == 0)
        {
            break;
        }

        QuicSubheader sub;
        data->RemoveHeader(sub);
        if (!sub.IsValid())
        {
            // RFC 9000 Section 12.4 and 19: the frame is truncated, malformed or of an unknown
            // type; nothing behind it in the packet can be read
            NS_LOG_WARN("Malformed frame, error " << sub.GetParseError());
            m_frameError = sub.GetParseError();
            break;
        }
        if (!sub.IsAllowedIn(m_recvPacketType))
        {
            // RFC 9000 Section 12.4: a frame that the packet type does not allow is a
            // PROTOCOL_VIOLATION
            NS_LOG_WARN("Frame " << sub.GetFrameType() << " not allowed in this packet type");
            m_frameError = QuicSubheader::PROTOCOL_VIOLATION;
            break;
        }

        // a STREAM frame with the LEN bit says how many bytes of data follow, which can be none;
        // one without it runs to the end of the packet
        uint64_t frameDataLen = sub.GetPayloadLength(data->GetSize());

        if (frameDataLen > data->GetSize())
        {
            NS_LOG_WARN("Frame data length " << frameDataLen << " exceeds remaining packet size "
                                             << data->GetSize());
            m_frameError = QuicSubheader::FRAME_ENCODING_ERROR;
            break;
        }

        NS_LOG_INFO("subheader " << sub << " dataSizeByte " << dataSizeByte << " remaining "
                                 << data->GetSize() << " frame size " << frameDataLen);
        // Copy the frame bytes instead of CreateFragment: the packet metadata of a received
        // datagram is not guaranteed to be fragmentable at arbitrary frame boundaries
        std::vector<uint8_t> frameBytes(frameDataLen);
        if (frameDataLen > 0)
        {
            data->CopyData(frameBytes.data(), frameDataLen);
        }
        Ptr<Packet> remainingfragment =
            (frameDataLen > 0) ? Create<Packet>(frameBytes.data(), frameDataLen) : Create<Packet>();
        NS_LOG_INFO("fragment size " << remainingfragment->GetSize());

        // remove the first portion of the packet
        data->RemoveAtStart(frameDataLen);
        start += sub.GetSerializedSize() + frameDataLen;
        disgregated.push_back(std::make_pair(remainingfragment, sub));
    }

    return disgregated;
}

Ptr<QuicStreamBase>
QuicL5Protocol::SearchStream(uint64_t streamId)
{
    auto it = m_streamById.find(streamId);
    return (it == m_streamById.end()) ? nullptr : it->second;
}

void
QuicL5Protocol::SetNode(Ptr<Node> node)
{
    NS_LOG_FUNCTION(this << node);
    m_node = node;
}

void
QuicL5Protocol::SetConnectionId(const QuicConnectionId& connId)
{
    NS_LOG_FUNCTION(this << connId);
    m_connectionId = connId;
}

uint16_t
QuicL5Protocol::GetMaxPacketSize() const
{
    return m_socket->GetPacketBudget();
}

bool
QuicL5Protocol::ContainsTransportParameters()
{
    return m_socket->CouldContainTransportParameters();
}

void
QuicL5Protocol::OnReceivedTransportParameters(QuicTransportParameters transportParameters)
{
    m_socket->OnReceivedTransportParameters(transportParameters);
}

void
QuicL5Protocol::SignalAbortConnection(uint16_t transportErrorCode, const char* reasonPhrase)
{
    NS_LOG_FUNCTION(this);
    m_socket->AbortConnection(transportErrorCode, reasonPhrase);
}

void
QuicL5Protocol::UpdateInitialMaxStreamData(void)
{
    for (auto stream : m_streams)
    {
        if (!stream->IsHandshake())
        {
            uint64_t id = stream->GetStreamId();
            stream->SetMaxStreamData(
                m_socket->GetPeerStreamDataLimit(IsLocallyInitiated(id), (id & 2) == 0));
        }
    }
}

uint64_t
QuicL5Protocol::GetMaxData()
{
    if (m_connMaxAllowed == 0)
    {
        m_connMaxAllowed = m_socket->GetConnRecvWindow();
    }
    return m_connMaxAllowed;
}

uint64_t
QuicL5Protocol::ConnectionSendWindow() const
{
    if (m_socket->GetSocketState() != QuicSocket::OPEN && !m_socket->IsFlushingOnClose())
    {
        return 0; // no application data before the handshake completes
    }
    uint64_t peerMax = m_socket->GetConnectionMaxData();
    return (peerMax > m_connSent) ? peerMax - m_connSent : 0;
}

void
QuicL5Protocol::OnNewDataSent(int64_t bytes)
{
    m_connSent += bytes;
}

void
QuicL5Protocol::OnBytesDelivered(uint64_t bytes)
{
    // msquic: MaxData slides with every delivered byte; the MAX_DATA frame goes out once
    // ConnFlowControlWindow / 4 bytes accumulated
    uint64_t window = m_socket->GetConnRecvWindow();
    if (m_connMaxAllowed == 0)
    {
        m_connMaxAllowed = window;
    }
    m_connMaxAllowed += bytes;
    m_connDeliveredAccumulator += bytes;
    if (m_connDeliveredAccumulator < window / 4)
    {
        return;
    }
    m_connDeliveredAccumulator = 0;
    QuicSubheader md = QuicSubheader::CreateMaxData(m_connMaxAllowed);
    Ptr<Packet> p = Create<Packet>(0);
    p->AddHeader(md);
    Send(p);
}

bool
QuicL5Protocol::IsAckPending() const
{
    return m_socket != nullptr && m_socket->HasAckPending();
}

void
QuicL5Protocol::OnConnectionWindowUpdate()
{
    for (auto stream : m_streams)
    {
        if (!stream->IsHandshake())
        {
            stream->WakeUp();
        }
    }
}

void
QuicL5Protocol::NotifySocketTxFull()
{
    NS_LOG_FUNCTION(this);
    m_socketTxFull = true;
}

void
QuicL5Protocol::OnSocketTxSpace()
{
    NS_LOG_FUNCTION(this << m_socketTxFull);
    if (!m_socketTxFull)
    {
        return;
    }
    m_socketTxFull = false;
    NS_LOG_INFO("The socket buffer has room again: waking " << m_streams.size() << " streams");
    for (auto stream : m_streams)
    {
        stream->WakeUp();
    }
}

bool
QuicL5Protocol::OnBytesReceivedAtOffset(uint64_t bytes)
{
    m_connRecvTotal += bytes;
    return m_connRecvTotal <= GetMaxData();
}

bool
QuicL5Protocol::HasPendingStreamData() const
{
    for (auto stream : m_streams)
    {
        if (!stream->IsHandshake() && stream->HasPendingData())
        {
            return true;
        }
    }
    return false;
}

void
QuicL5Protocol::ReportConnectionBlockedIfNeeded()
{
    uint64_t limit = m_socket->GetConnectionMaxData();
    if (m_connSent >= limit && limit > 0 && m_connBlockedReportedAt != limit)
    {
        m_connBlockedReportedAt = limit;
        Ptr<Packet> p = Create<Packet>(0);
        p->AddHeader(QuicSubheader::CreateBlocked(limit));
        Send(p);
    }
}

Time
QuicL5Protocol::GetSmoothedRtt() const
{
    return m_socket->GetSmoothedRtt();
}

void
QuicL5Protocol::NotifyStreamBacklog(uint64_t streamId, bool backlogged)
{
    if (m_socket != nullptr)
    {
        m_socket->SetStreamBacklog(streamId, backlogged);
    }
}

bool
QuicL5Protocol::ResetStream(uint64_t streamId, uint64_t errorCode)
{
    Ptr<QuicStreamBase> stream = SearchStream(streamId);
    return stream != nullptr && stream->Reset(errorCode);
}

bool
QuicL5Protocol::StopSendingOnStream(uint64_t streamId, uint64_t errorCode)
{
    Ptr<QuicStreamBase> stream = SearchStream(streamId);
    return stream != nullptr && stream->StopSending(errorCode);
}

bool
QuicL5Protocol::FinishStream(uint64_t streamId)
{
    Ptr<QuicStreamBase> stream = SearchStream(streamId);
    return stream != nullptr && stream->Finish();
}

} // namespace ns3
