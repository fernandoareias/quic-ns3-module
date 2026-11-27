/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * @file
 * The handshake of a QUIC connection (RFC 9001): TLS 1.3 messages in CRYPTO frames of Initial and
 * Handshake packets, each level with its own packet number space, ACKs and retransmission. The
 * cryptography is emulated: the messages have the sizes of a real handshake (QuicTlsEmulator) and
 * the keys are only states that become available and are discarded.
 *
 * The 1-RTT and 0-RTT packets, the data of the connection and the recovery of those go through the
 * rest of QuicSocketBase.
 */

#include "quic-congestion-ops.h"
#include "quic-l4-protocol.h"
#include "quic-qlog-writer.h"
#include "quic-socket-base.h"
#include "quic-wire.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicSocketHandshake");

namespace
{

/** Bytes of a datagram that carries handshake packets, before PADDING. */
constexpr uint32_t HANDSHAKE_DATAGRAM = 1200;

/** Largest number of bytes of CRYPTO data kept for a level (RFC 9000, Section 7.5). */
constexpr uint64_t CRYPTO_BUFFER_LIMIT = 32768;

/** Packets of a level that are declared lost by a later acknowledged one (RFC 9002, Section 6.1.1). */
constexpr uint64_t HANDSHAKE_PACKET_THRESHOLD = 3;

/** TLS alert no_application_protocol as a QUIC error code (RFC 9001, Section 4.8). */
constexpr uint64_t CRYPTO_ERROR_NO_APPLICATION_PROTOCOL = 0x100 + 120;

/**
 * The ranges that an ACK frame acknowledges.
 *
 * @param sub the frame.
 * @return the pairs of smallest and largest packet number.
 */
std::vector<std::pair<uint64_t, uint64_t>>
AckedRanges(const QuicSubheader& sub)
{
    std::vector<std::pair<uint64_t, uint64_t>> out;
    const std::vector<uint64_t>& gaps = sub.GetGaps();
    const std::vector<uint64_t>& blocks = sub.GetAdditionalAckBlocks();
    const uint64_t count =
        std::min<uint64_t>(sub.GetAckBlockCount(), std::min(gaps.size(), blocks.size()));
    uint64_t high = sub.GetLargestAcknowledged();
    for (uint64_t k = 0; k <= count; ++k)
    {
        const uint64_t low = k < count ? gaps[k] + 1 : sub.GetFirstAckBlock();
        out.emplace_back(low, high);
        if (k < count)
        {
            high = blocks[k];
        }
    }
    return out;
}

/**
 * @param text names separated by commas.
 * @return the names.
 */
std::vector<std::string>
SplitNames(const std::string& text)
{
    std::vector<std::string> names;
    std::stringstream in(text);
    std::string name;
    while (std::getline(in, name, ','))
    {
        if (!name.empty())
        {
            names.push_back(name);
        }
    }
    return names;
}

} // namespace

void
QuicSocketBase::StartClientHandshake()
{
    NS_LOG_FUNCTION(this);
    if (!QuicTlsProfile::FromName(m_tlsProfileName, m_tlsProfile))
    {
        NS_FATAL_ERROR("Unknown TLS profile " << m_tlsProfileName);
    }
    m_tlsProfile.chainLength = m_tlsChainLength;
    m_tcb->m_cWnd = m_tcb->m_initialCWnd;
    m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
    m_hs[0].keys = true;
    if (!m_retryReceived && InetSocketAddress::IsMatchingType(m_connectAddress))
    {
        // a token of an earlier connection (NEW_TOKEN) lets the server skip its Retry
        m_initialToken =
            m_quicl4->GetRememberedToken(InetSocketAddress::ConvertFrom(m_connectAddress).GetIpv4());
    }
    m_resumptionTicket = 0;
    if (InetSocketAddress::IsMatchingType(m_connectAddress))
    {
        m_resumptionTicket = m_quicl4->GetRememberedTicket(
            InetSocketAddress::ConvertFrom(m_connectAddress).GetIpv4());
    }
    const QuicTransportParameters tp = OnSendingTransportParameters();
    m_hs[0].crypto.Queue(
        QuicTlsEmulator::ClientHello(m_tlsProfile, tp, SplitNames(m_alpn), m_resumptionTicket));
    FlushHandshake();
}

void
QuicSocketBase::HandleRetry(const QuicHeader& header)
{
    NS_LOG_FUNCTION(this);
    // RFC 9000, Section 17.2.5.2: only one Retry is accepted, none after a packet of the server
    // was processed, and one that has the id the client addressed is not valid
    if (m_retryReceived || m_tlsHelloDone || header.GetToken().empty() ||
        header.GetSourceConnectionId().IsEmpty() ||
        header.GetSourceConnectionId() == m_initialDcid)
    {
        NotifyPacketDropped(&header, header.GetSerializedSize(), "invalid", "Retry not valid");
        return;
    }
    m_retryReceived = true;
    m_retrySourceCid = header.GetSourceConnectionId();
    m_initialToken = header.GetToken();
    m_peerCid = m_retrySourceCid;
    m_hsPtoCount = 0;
    HandshakeSpace& space = m_hs[0];
    space.sent.clear();
    space.crypto.OnLost(0, space.crypto.QueuedBytes());
    FlushHandshake();
}

void
QuicSocketBase::ResetHandshake()
{
    m_hsTimer.Cancel();
    m_hsPtoCount = 0;
    for (auto& space : m_hs)
    {
        space = HandshakeSpace();
    }
    m_tlsHelloDone = false;
    m_tlsCertificateSeen = false;
    m_handshakeComplete = false;
}

Ptr<Packet>
QuicSocketBase::BuildHandshakeAck(int level)
{
    HandshakeSpace& space = m_hs[level];
    const auto& ranges = space.received.Ranges();
    auto it = ranges.rbegin();
    const uint32_t largest = it->second;
    std::vector<uint64_t> blocks;
    std::vector<uint64_t> gaps;
    uint32_t floor = it->first;
    for (auto prev = it++; it != ranges.rend() && gaps.size() < m_maxTrackedGaps; prev = it++)
    {
        blocks.push_back(it->second);
        gaps.push_back(prev->first - 1);
        floor = it->first;
    }
    // RFC 9000, Section 19.3.1: the ack delay of Initial and Handshake packets uses the default
    // exponent, 3
    const uint64_t delay = (Simulator::Now() - space.largestRecvTime).GetMicroSeconds() >> 3;
    Ptr<Packet> frame = Create<Packet>();
    frame->AddHeader(QuicSubheader::CreateAck(largest, delay, floor, gaps, blocks));
    return frame;
}

void
QuicSocketBase::FlushHandshake()
{
    NS_LOG_FUNCTION(this);
    if (m_socketState == CLOSING || m_socketState == IDLE)
    {
        return;
    }
    for (int guard = 0; guard < 64; ++guard)
    {
        // RFC 9000, Section 8.1: a server that has not validated the address of the client sends
        // at most three times what it received
        uint32_t limit = HANDSHAKE_DATAGRAM;
        const bool limited = m_isServerSide && !m_peerAddressValidated;
        if (limited)
        {
            const uint64_t allowed = 3 * m_bytesReceivedPreValidation > m_bytesSentPreValidation
                                         ? 3 * m_bytesReceivedPreValidation - m_bytesSentPreValidation
                                         : 0;
            limit = std::min<uint64_t>(limit, allowed);
        }

        std::vector<std::pair<QuicHeader, Ptr<Packet>>> packets;
        std::vector<std::pair<int, HandshakeSpace::Sent>> records;
        std::vector<uint64_t> numbers;
        uint32_t used = 0;
        bool initialAckEliciting = false;
        bool ackEliciting = false;

        for (int level = 0; level < 2; ++level)
        {
            HandshakeSpace& space = m_hs[level];
            if (space.discarded || !space.keys)
            {
                continue;
            }
            const bool wantAck = space.ackPending && !space.received.Empty();
            const bool wantData = space.crypto.HasDataToSend();
            if (!wantAck && !wantData && !space.pingPending)
            {
                continue;
            }
            QuicHeader head =
                level == 0
                    ? QuicHeader::CreateInitial(GetDestCid(),
                                                m_connectionId,
                                                m_vers,
                                                QuicPacketNumber(space.nextPn),
                                                m_isServerSide ? std::vector<uint8_t>()
                                                               : m_initialToken)
                    : QuicHeader::CreateHandshake(GetDestCid(),
                                                  m_connectionId,
                                                  m_vers,
                                                  QuicPacketNumber(space.nextPn));
            head.SetPayloadSize(HANDSHAKE_DATAGRAM);
            const uint32_t overhead = head.GetSerializedSize() + QUIC_AEAD_TAG_SIZE;
            if (limit < used + overhead + 24)
            {
                continue;
            }
            uint32_t room = limit - used - overhead;
            Ptr<Packet> payload = Create<Packet>();
            HandshakeSpace::Sent record;
            record.time = Simulator::Now();
            if (wantAck)
            {
                Ptr<Packet> ack = BuildHandshakeAck(level);
                if (ack->GetSize() < room)
                {
                    room -= ack->GetSize();
                    payload->AddAtEnd(ack);
                }
            }
            uint64_t offset;
            std::vector<uint8_t> data;
            while (room > 16 && space.crypto.NextChunk(room - 12, offset, data))
            {
                Ptr<Packet> frame = Create<Packet>(data.data(), data.size());
                frame->AddHeader(QuicSubheader::CreateCrypto(offset, data.size()));
                room -= std::min<uint32_t>(room, frame->GetSize());
                payload->AddAtEnd(frame);
                record.crypto.emplace_back(offset, data.size());
                record.ackEliciting = true;
            }
            if (space.pingPending)
            {
                space.pingPending = false;
                Ptr<Packet> ping = Create<Packet>();
                ping->AddHeader(QuicSubheader::CreatePing());
                payload->AddAtEnd(ping);
                record.ackEliciting = true;
            }
            if (payload->GetSize() == 0)
            {
                continue;
            }
            space.ackPending = false;
            if (record.ackEliciting)
            {
                ackEliciting = true;
            }
            if (level == 0 && (record.ackEliciting || !m_isServerSide))
            {
                // a client expands every datagram with an Initial packet, a server those with an
                // ack-eliciting one
                initialAckEliciting = true;
            }
            used += overhead + payload->GetSize();
            packets.emplace_back(head, payload);
            records.emplace_back(level, record);
            numbers.push_back(space.nextPn);
            ++space.nextPn;
        }
        if (packets.empty())
        {
            break;
        }

        // RFC 9000, Section 14.1: the datagram of a client Initial packet, or of an ack-eliciting
        // server Initial packet, has 1200 bytes or more
        uint32_t minimum = 0;
        if (initialAckEliciting)
        {
            minimum = std::max<uint32_t>(HANDSHAKE_DATAGRAM, GetInitialPacketSize());
        }
        const uint32_t datagram = std::max(used, minimum);
        m_quicl4->SendDatagram(this, packets, minimum);
        if (limited)
        {
            m_bytesSentPreValidation += datagram;
        }
        for (size_t k = 0; k < packets.size(); ++k)
        {
            HandshakeSpace& space = m_hs[records[k].first];
            space.sent[numbers[k]] = records[k].second;
            if (records[k].second.ackEliciting)
            {
                space.lastAckElicitingSent = Simulator::Now();
            }
            NotifyPacketSent(packets[k].second, packets[k].first);
        }
        if (ackEliciting)
        {
            m_lastPacketSent = Simulator::Now();
            // RFC 9000, Section 10.1: the idle timer restarts when the first ack-eliciting packet is
            // sent after a packet was received, not when a packet is sent again
            if (!m_hsSentSinceReceive && !m_drainingPeriodEvent.IsPending())
            {
                m_hsSentSinceReceive = true;
                ArmIdleTimer();
            }
        }
    }
    ArmHandshakeTimer();
}

void
QuicSocketBase::HandleHandshakePacket(Ptr<Packet> p, const QuicHeader& header)
{
    NS_LOG_FUNCTION(this);
    const int level = header.IsInitial() ? 0 : 1;
    HandshakeSpace& space = m_hs[level];
    if (m_isServerSide && level == 0 && !space.discarded)
    {
        // the Initial keys come from the Destination Connection ID of the first packet
        space.keys = true;
    }
    if (space.discarded || !space.keys)
    {
        NS_LOG_INFO("Dropping a packet of a level whose keys are not available");
        NotifyPacketDropped(&header, p->GetSize(), "keys_unavailable", "");
        return;
    }
    const uint64_t number = header.GetPacketNumber().GetValue();
    if (space.received.Contains(number))
    {
        NotifyPacketDropped(&header, p->GetSize(), "duplicate", "");
        return;
    }
    if (m_isServerSide && !m_peerAddressValidated)
    {
        m_bytesReceivedPreValidation += header.GetSerializedSize() + p->GetSize() + QUIC_AEAD_TAG_SIZE;
        if (level == 1)
        {
            // RFC 9000, Section 8.1: a Handshake packet proves the client got the packets that
            // were sent to its address
            m_peerAddressValidated = true;
        }
    }
    space.received.Add(number);
    space.largestRecvTime = Simulator::Now();

    bool ackEliciting = false;
    Ptr<Packet> rest = p->Copy();
    while (rest->GetSize() > 0)
    {
        QuicSubheader sub;
        rest->RemoveHeader(sub);
        if (!sub.IsValid())
        {
            AbortConnection(static_cast<QuicSubheader::TransportErrorCodes_t>(sub.GetParseError()),
                            "Malformed frame");
            return;
        }
        const QuicPacketType type = level == 0 ? QuicPacketType::INITIAL : QuicPacketType::HANDSHAKE;
        if (!sub.IsAllowedIn(type))
        {
            AbortConnection(QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                            "A frame that an Initial or Handshake packet may not carry");
            return;
        }
        const uint64_t length = sub.GetPayloadLength(rest->GetSize());
        if (length > rest->GetSize())
        {
            AbortConnection(QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
                            "Frame longer than its packet");
            return;
        }
        std::vector<uint8_t> data(length);
        if (length > 0)
        {
            rest->CopyData(data.data(), length);
            rest->RemoveAtStart(length);
        }
        if (sub.IsAck())
        {
            HandleHandshakeAck(level, sub);
        }
        else if (sub.IsCrypto())
        {
            ackEliciting = true;
            if (!space.crypto.OnFrame(sub.GetOffset(), data, CRYPTO_BUFFER_LIMIT))
            {
                AbortConnection(QuicSubheader::TransportErrorCodes_t::CRYPTO_BUFFER_EXCEEDED,
                                "CRYPTO data beyond the limit");
                return;
            }
        }
        else if (sub.IsPing())
        {
            ackEliciting = true;
        }
        else if (sub.IsConnectionClose())
        {
            QlogClosed("remote",
                       sub.GetErrorCode() == 0 ? "application" : "error",
                       sub.GetErrorCode(),
                       true,
                       false,
                       std::string(sub.GetReasonPhrase().begin(), sub.GetReasonPhrase().end()));
            EnterDraining();
            return;
        }
    }
    if (ackEliciting)
    {
        space.ackPending = true;
    }
    ProcessTls(level);
    if (level == 1 && m_isServerSide)
    {
        // RFC 9001, Section 4.9.1: a server discards the Initial keys when it first processes a
        // Handshake packet
        DiscardHandshakeLevel(0);
    }
    if (m_socketState != CLOSING && m_socketState != IDLE && !m_hsFlushEvent.IsPending())
    {
        // the packets of one datagram are handled one after the other: what they make the
        // endpoint send goes out together, coalesced
        m_hsFlushEvent = Simulator::ScheduleNow(&QuicSocketBase::FlushHandshake, this);
    }
}

void
QuicSocketBase::HandleHandshakeAck(int level, const QuicSubheader& sub)
{
    HandshakeSpace& space = m_hs[level];
    const auto ranges = AckedRanges(sub);
    const uint64_t largest = sub.GetLargestAcknowledged();
    bool newly = false;
    bool largestNew = false;
    Time sentTime;
    bool largestEliciting = false;
    for (auto it = space.sent.begin(); it != space.sent.end();)
    {
        bool acked = false;
        for (const auto& range : ranges)
        {
            if (it->first >= range.first && it->first <= range.second)
            {
                acked = true;
                break;
            }
        }
        if (!acked)
        {
            ++it;
            continue;
        }
        newly = true;
        for (const auto& c : it->second.crypto)
        {
            space.crypto.OnAcked(c.first, c.second);
        }
        if (it->first == largest)
        {
            largestNew = true;
            sentTime = it->second.time;
            largestEliciting = it->second.ackEliciting;
        }
        m_packetAckedTrace(it->first, 0);
        it = space.sent.erase(it);
    }
    space.largestAcked = std::max<int64_t>(space.largestAcked, static_cast<int64_t>(largest));
    if (largestNew && largestEliciting && m_congestionControl)
    {
        // RFC 9002, Section 5.3: the delay the peer reports is not used for Initial packets, and
        // the Handshake space has no max_ack_delay either
        DynamicCast<QuicCongestionOps>(m_congestionControl)
            ->UpdateRtt(m_tcb, Simulator::Now() - sentTime, Seconds(0));
        SetLastRtt(m_tcb->m_latestRtt);
    }
    if (newly)
    {
        m_hsPtoCount = 0;
    }
    // RFC 9002, Section 6.1.1: a packet is lost when one sent three packets later was acknowledged
    for (auto it = space.sent.begin(); it != space.sent.end();)
    {
        if (static_cast<uint64_t>(space.largestAcked) >= it->first + HANDSHAKE_PACKET_THRESHOLD)
        {
            for (const auto& c : it->second.crypto)
            {
                space.crypto.OnLost(c.first, c.second);
            }
            m_packetLostTrace(it->first, 0, "reordering_threshold");
            if (m_qlog)
            {
                QlogStart();
                m_qlog->PacketLost(it->first, "reordering_threshold");
            }
            it = space.sent.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void
QuicSocketBase::ProcessTls(int level)
{
    HandshakeSpace& space = m_hs[level];
    std::vector<uint8_t> bytes = space.crypto.Read();
    if (bytes.empty())
    {
        return;
    }
    space.parser.Append(bytes);
    uint8_t type;
    std::vector<uint8_t> body;
    while (m_socketState != CLOSING && m_socketState != IDLE && space.parser.Next(type, body))
    {
        if (!HandleTlsMessage(level, type, body))
        {
            return;
        }
    }
}

bool
QuicSocketBase::HandleTlsMessage(int level, uint8_t type, const std::vector<uint8_t>& body)
{
    NS_LOG_FUNCTION(this << level << (uint32_t)type);
    std::vector<uint8_t> data;
    if (m_isServerSide)
    {
        if (level == 0 && type == TLS_CLIENT_HELLO && !m_tlsHelloDone)
        {
            m_tlsHelloDone = true;
            QuicTransportParameters tp;
            if (!QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_TRANSPORT_PARAMETERS, data) ||
                !QuicTlsParser::ParseTransportParameters(data, tp))
            {
                AbortConnection(QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
                                "Missing or invalid transport parameters");
                return false;
            }
            std::vector<std::string> offered;
            if (!QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_ALPN, data) ||
                !QuicTlsParser::ParseAlpn(data, offered))
            {
                AbortConnection(static_cast<QuicSubheader::TransportErrorCodes_t>(
                                    CRYPTO_ERROR_NO_APPLICATION_PROTOCOL),
                                "No application protocol offered");
                return false;
            }
            const std::vector<std::string> mine = SplitNames(m_alpn);
            m_alpnChosen.clear();
            for (const auto& name : offered)
            {
                if (std::find(mine.begin(), mine.end(), name) != mine.end())
                {
                    m_alpnChosen = name;
                    break;
                }
            }
            if (m_alpnChosen.empty())
            {
                AbortConnection(static_cast<QuicSubheader::TransportErrorCodes_t>(
                                    CRYPTO_ERROR_NO_APPLICATION_PROTOCOL),
                                "No application protocol in common");
                return false;
            }
            OnReceivedTransportParameters(tp);
            if (m_socketState == CLOSING || m_socketState == IDLE)
            {
                return false;
            }
            // RFC 8446, Section 4.2.11: a ClientHello with a ticket this server issued may carry
            // early data, which a server whose stack allows 0-RTT accepts
            std::vector<uint8_t> psk;
            m_earlyDataAccepted =
                m_quicl4->Is0RTTHandshakeAllowed() &&
                QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_PRE_SHARED_KEY, psk) &&
                m_quicl4->IsTicketValid(QuicTlsParser::ParseTicketIdentity(psk));
            if (!QuicTlsProfile::FromName(m_tlsProfileName, m_tlsProfile))
            {
                NS_FATAL_ERROR("Unknown TLS profile " << m_tlsProfileName);
            }
            m_tlsProfile.chainLength = m_tlsChainLength;
            m_hs[0].crypto.Queue(QuicTlsEmulator::ServerHello(m_tlsProfile));
            m_hs[1].keys = true;
            m_hs[1].crypto.Queue(QuicTlsEmulator::ServerFlight(m_tlsProfile,
                                                               OnSendingTransportParameters(),
                                                               m_alpnChosen));
            m_tcb->m_cWnd = m_tcb->m_initialCWnd;
            m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
            return true;
        }
        if (level == 1 && type == TLS_CERTIFICATE)
        {
            m_tlsCertificateSeen = true;
            return true;
        }
        if (level == 1 && type == TLS_FINISHED)
        {
            if (m_tlsProfile.clientAuth && !m_tlsCertificateSeen)
            {
                AbortConnection(static_cast<QuicSubheader::TransportErrorCodes_t>(0x100 + 116),
                                "Certificate required");
                return false;
            }
            CompleteServerHandshake();
        }
        return true;
    }

    // client
    if (level == 0 && type == TLS_SERVER_HELLO && !m_tlsHelloDone)
    {
        m_tlsHelloDone = true;
        m_hs[1].keys = true;
        return true;
    }
    if (level == 1 && type == TLS_ENCRYPTED_EXTENSIONS)
    {
        QuicTransportParameters tp;
        if (!QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_TRANSPORT_PARAMETERS, data) ||
            !QuicTlsParser::ParseTransportParameters(data, tp))
        {
            AbortConnection(QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
                            "Missing or invalid transport parameters");
            return false;
        }
        std::vector<std::string> chosen;
        const std::vector<std::string> mine = SplitNames(m_alpn);
        if (!QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_ALPN, data) ||
            !QuicTlsParser::ParseAlpn(data, chosen) || chosen.size() != 1 ||
            std::find(mine.begin(), mine.end(), chosen[0]) == mine.end())
        {
            AbortConnection(static_cast<QuicSubheader::TransportErrorCodes_t>(
                                CRYPTO_ERROR_NO_APPLICATION_PROTOCOL),
                            "The server chose a protocol that was not offered");
            return false;
        }
        m_alpnChosen = chosen[0];
        OnReceivedTransportParameters(tp);
        return m_socketState != CLOSING && m_socketState != IDLE;
    }
    if (level == 1 && type == TLS_CERTIFICATE)
    {
        m_tlsCertificateSeen = true;
        return true;
    }
    if (level == 1 && type == TLS_FINISHED)
    {
        CompleteClientHandshake();
    }
    return true;
}

void
QuicSocketBase::CompleteClientHandshake()
{
    NS_LOG_FUNCTION(this);
    if (m_handshakeComplete)
    {
        return;
    }
    m_handshakeComplete = true;
    m_hs[1].crypto.Queue(QuicTlsEmulator::ClientFlight(m_tlsProfile));
    // RFC 9001, Section 4.9.1: the client discards the Initial keys when it first sends a Handshake
    // packet; the Handshake packet that follows goes out before the keys are dropped
    FlushHandshake();
    DiscardHandshakeLevel(0);
    m_zeroRttConnect = false;
    if (m_socketState == CONNECTING_CLT)
    {
        m_connected = true;
        SetState(OPEN);
        Simulator::ScheduleNow(&QuicSocketBase::ConnectionSucceeded, Ptr<QuicSocketBase>(this));
        m_congestionControl->CongestionStateSet(m_tcb, TcpSocketState::CA_OPEN);
    }
}

void
QuicSocketBase::CompleteServerHandshake()
{
    NS_LOG_FUNCTION(this);
    if (m_handshakeComplete)
    {
        return;
    }
    m_handshakeComplete = true;
    m_peerAddressValidated = true;
    m_tcb->m_handshakeConfirmed = true;
    // the ACKs that are owed to the client go out in this flush, then the keys are discarded
    FlushHandshake();
    DiscardHandshakeLevel(0);
    DiscardHandshakeLevel(1);
    m_connected = true;
    SetState(OPEN);
    Simulator::ScheduleNow(&QuicSocketBase::ConnectionSucceeded, Ptr<QuicSocketBase>(this));
    m_congestionControl->CongestionStateSet(m_tcb, TcpSocketState::CA_OPEN);
    // RFC 9000, Section 19.20: the server confirms the handshake
    SendControlFrame(QuicSubheader::CreateHandshakeDone());
    // RFC 8446, Section 4.6.1: and a session ticket that lets it send 0-RTT data next time
    SendApplicationCrypto(QuicTlsEmulator::NewSessionTicket(m_tlsProfile, m_quicl4->IssueTicket()));
    // RFC 9000, Section 8.1.3: and gives the client a token for its next connection
    if (InetSocketAddress::IsMatchingType(GetActiveRemote()))
    {
        SendControlFrame(QuicSubheader::CreateNewToken(
            m_quicl4->IssueNewToken(InetSocketAddress::ConvertFrom(GetActiveRemote()).GetIpv4())));
    }
    SendPendingData(true);
}

void
QuicSocketBase::DiscardHandshakeLevel(int level)
{
    HandshakeSpace& space = m_hs[level];
    if (space.discarded)
    {
        return;
    }
    NS_LOG_INFO("Discarding the keys of handshake level " << level);
    space.discarded = true;
    space.keys = false;
    space.sent.clear();
    space.crypto.Discard();
    space.ackPending = false;
    space.pingPending = false;
    if (level == 0)
    {
        DiscardInitialPacketSpace();
    }
    else
    {
        DiscardHandshakePacketSpace();
    }
    ArmHandshakeTimer();
}

void
QuicSocketBase::ArmHandshakeTimer()
{
    m_hsTimer.Cancel();
    bool inFlight = false;
    Time earliest = Time::Max();
    const Time pto = ProbeTimeout(false) * (1u << std::min(m_hsPtoCount, 30u));
    for (const auto& space : m_hs)
    {
        if (space.discarded)
        {
            continue;
        }
        for (const auto& entry : space.sent)
        {
            if (entry.second.ackEliciting)
            {
                inFlight = true;
            }
        }
        if (inFlight && space.lastAckElicitingSent.IsStrictlyPositive())
        {
            earliest = std::min(earliest, space.lastAckElicitingSent + pto);
        }
    }
    const bool clientWaiting = !m_isServerSide && !m_handshakeDoneReceived && !m_hs[0].discarded;
    if (!inFlight && !clientWaiting)
    {
        return;
    }
    // RFC 9002, Section 6.2.2.1: a client that has nothing in flight still arms the timer until
    // the handshake is confirmed, as the server may be blocked by the limit of three times
    if (!inFlight)
    {
        earliest = Simulator::Now() + pto;
    }
    // RFC 9002, Section 6.2.2.1: a server at its limit does not arm the timer
    if (m_isServerSide && !m_peerAddressValidated && m_bytesReceivedPreValidation > 0 &&
        m_bytesSentPreValidation >= 3 * m_bytesReceivedPreValidation)
    {
        return;
    }
    if (earliest == Time::Max())
    {
        return;
    }
    Time delay = earliest - Simulator::Now();
    if (delay.IsNegative())
    {
        delay = Seconds(0);
    }
    m_hsTimer = Simulator::Schedule(delay, &QuicSocketBase::OnHandshakeTimeout, this);
}

void
QuicSocketBase::OnHandshakeTimeout()
{
    NS_LOG_FUNCTION(this);
    if (m_socketState == CLOSING || m_socketState == IDLE)
    {
        return;
    }
    ++m_hsPtoCount;
    m_ptoTrace(m_hsPtoCount, ProbeTimeout(false) * (1u << std::min(m_hsPtoCount, 30u)));
    bool resend = false;
    for (auto& space : m_hs)
    {
        if (space.discarded)
        {
            continue;
        }
        for (const auto& entry : space.sent)
        {
            for (const auto& c : entry.second.crypto)
            {
                space.crypto.OnLost(c.first, c.second);
                resend = true;
            }
        }
        space.sent.clear();
    }
    if (!resend)
    {
        // nothing to send again: a PING in the highest level probes the path (RFC 9002,
        // Section 6.2.2.1)
        for (int level = 1; level >= 0; --level)
        {
            if (!m_hs[level].discarded && m_hs[level].keys)
            {
                m_hs[level].pingPending = true;
                break;
            }
        }
    }
    FlushHandshake();
}

void
QuicSocketBase::SendApplicationCrypto(const std::vector<uint8_t>& data)
{
    Ptr<Packet> p = Create<Packet>(data.data(), data.size());
    p->AddHeader(QuicSubheader::CreateCrypto(m_appCryptoOffset, data.size()));
    m_appCryptoOffset += data.size();
    AppendingTx(p);
}

void
QuicSocketBase::OnReceivedApplicationCrypto(const QuicSubheader& sub, Ptr<Packet> data)
{
    if (m_isServerSide)
    {
        // RFC 9001, Section 4.6: only a server sends NewSessionTicket
        AbortConnection(QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                        "CRYPTO data received by a server in a 1-RTT packet");
        return;
    }
    std::vector<uint8_t> bytes(data->GetSize());
    if (!bytes.empty())
    {
        data->CopyData(bytes.data(), bytes.size());
    }
    if (!m_appCryptoRx.OnFrame(sub.GetOffset(), bytes, CRYPTO_BUFFER_LIMIT))
    {
        AbortConnection(QuicSubheader::TransportErrorCodes_t::CRYPTO_BUFFER_EXCEEDED,
                        "CRYPTO data beyond the limit");
        return;
    }
    m_appParser.Append(m_appCryptoRx.Read());
    uint8_t type;
    std::vector<uint8_t> body;
    while (m_appParser.Next(type, body))
    {
        uint64_t ticket;
        if (type == TLS_NEW_SESSION_TICKET && QuicTlsParser::ParseTicket(body, ticket) &&
            InetSocketAddress::IsMatchingType(m_connectAddress))
        {
            // the ticket and the parameters of the server serve a later connection
            const Ipv4Address server = InetSocketAddress::ConvertFrom(m_connectAddress).GetIpv4();
            m_quicl4->RememberTicket(server, ticket);
            m_quicl4->RememberServerParameters(server, m_peerParameters);
        }
    }
}

} // namespace ns3
