/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-cubic.h"

#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <cmath>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicCubic");
NS_OBJECT_ENSURE_REGISTERED(QuicCubic);

namespace
{
constexpr uint32_t kHyStartMinSamples = 8;
constexpr uint32_t kHyStartCssRounds = 5;
constexpr uint32_t kHyStartCssGrowthDivisor = 4;
const Time kHyStartMinEta = MilliSeconds(4);
const Time kHyStartMaxEta = MilliSeconds(16);
} // namespace

TypeId
QuicCubic::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicCubic")
                            .SetParent<QuicCongestionOps>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicCubic>()
                            .AddAttribute("C",
                                          "CUBIC scaling constant (segments per s^3)",
                                          DoubleValue(0.4),
                                          MakeDoubleAccessor(&QuicCubic::m_c),
                                          MakeDoubleChecker<double>(0))
                            .AddAttribute("Beta",
                                          "CUBIC multiplicative decrease factor",
                                          DoubleValue(0.7),
                                          MakeDoubleAccessor(&QuicCubic::m_beta),
                                          MakeDoubleChecker<double>(0, 1))
                            .AddAttribute("HyStart",
                                          "Enable HyStart++ (RFC 9406); msquic ships it disabled "
                                          "(QUIC_DEFAULT_HYSTART_ENABLED)",
                                          BooleanValue(false),
                                          MakeBooleanAccessor(&QuicCubic::m_hyStartEnabled),
                                          MakeBooleanChecker())
                            .AddAttribute("Pacing",
                                          "Pace the sending of packets",
                                          BooleanValue(true),
                                          MakeBooleanAccessor(&QuicCubic::m_pacingEnabled),
                                          MakeBooleanChecker());
    return tid;
}

QuicCubic::QuicCubic()
    : QuicCongestionOps(),
      m_c(0.4),
      m_beta(0.7),
      m_windowMax(0),
      m_windowLastMax(0),
      m_k(0),
      m_aimdWindow(0),
      m_congAvoidStart(Seconds(0)),
      m_epochStarted(false),
      m_hyStartEnabled(false),
      m_hyState(HS_NOT_STARTED),
      m_roundEnd(0),
      m_roundEndSet(false),
      m_lastRoundMinRtt(Time::Max()),
      m_currRoundMinRtt(Time::Max()),
      m_rttSamples(0),
      m_cssRounds(0),
      m_cssBaselineMinRtt(Time::Max()),
      m_pacingEnabled(true),
      m_bytesInFlightMax(0)
{
    NS_LOG_FUNCTION(this);
}

QuicCubic::QuicCubic(const QuicCubic& other)
    : QuicCongestionOps(other),
      m_c(other.m_c),
      m_beta(other.m_beta),
      m_windowMax(other.m_windowMax),
      m_windowLastMax(other.m_windowLastMax),
      m_k(other.m_k),
      m_aimdWindow(other.m_aimdWindow),
      m_congAvoidStart(other.m_congAvoidStart),
      m_epochStarted(other.m_epochStarted),
      m_hyStartEnabled(other.m_hyStartEnabled),
      m_hyState(other.m_hyState),
      m_roundEnd(other.m_roundEnd),
      m_roundEndSet(other.m_roundEndSet),
      m_lastRoundMinRtt(other.m_lastRoundMinRtt),
      m_currRoundMinRtt(other.m_currRoundMinRtt),
      m_rttSamples(other.m_rttSamples),
      m_cssRounds(other.m_cssRounds),
      m_cssBaselineMinRtt(other.m_cssBaselineMinRtt),
      m_pacingEnabled(other.m_pacingEnabled),
      m_bytesInFlightMax(other.m_bytesInFlightMax)
{
}

QuicCubic::~QuicCubic()
{
}

std::string
QuicCubic::GetName() const
{
    return "QuicCubic";
}

Ptr<TcpCongestionOps>
QuicCubic::Fork()
{
    return CopyObject<QuicCubic>(this);
}

void
QuicCubic::HyStartOnAck(Ptr<QuicSocketState> tcbd, SequenceNumber32 pn)
{
    if (!m_hyStartEnabled || tcbd->m_cWnd >= tcbd->m_ssThresh)
    {
        return;
    }
    if (m_hyState == HS_NOT_STARTED)
    {
        m_hyState = HS_STARTED;
    }
    if (tcbd->m_latestRtt > Seconds(0))
    {
        m_currRoundMinRtt = std::min(m_currRoundMinRtt, tcbd->m_latestRtt);
        ++m_rttSamples;
    }
    if (!m_roundEndSet)
    {
        m_roundEnd = tcbd->m_highTxMark;
        m_roundEndSet = true;
        return;
    }
    if (pn < m_roundEnd)
    {
        return;
    }

    // A round ended: evaluate the RTT increase (RFC 9406 s4.2)
    if (m_hyState == HS_STARTED)
    {
        if (m_rttSamples >= kHyStartMinSamples && m_lastRoundMinRtt != Time::Max())
        {
            Time eta = std::max(kHyStartMinEta, std::min(m_lastRoundMinRtt / 8, kHyStartMaxEta));
            if (m_currRoundMinRtt >= m_lastRoundMinRtt + eta)
            {
                NS_LOG_INFO("HyStart++: RTT increase, entering conservative slow start");
                m_cssBaselineMinRtt = m_currRoundMinRtt;
                m_cssRounds = 0;
                m_hyState = HS_ACTIVE;
            }
        }
    }
    else if (m_hyState == HS_ACTIVE)
    {
        if (m_rttSamples >= kHyStartMinSamples)
        {
            if (m_currRoundMinRtt < m_cssBaselineMinRtt)
            {
                NS_LOG_INFO("HyStart++: RTT decreased, back to slow start");
                m_hyState = HS_STARTED;
            }
            else if (++m_cssRounds >= kHyStartCssRounds)
            {
                NS_LOG_INFO("HyStart++: leaving slow start");
                tcbd->m_ssThresh = tcbd->m_cWnd;
                m_windowMax = tcbd->m_cWnd;
                m_windowLastMax = tcbd->m_cWnd;
                m_epochStarted = false;
                m_aimdWindow = tcbd->m_cWnd;
            }
        }
    }
    if (m_rttSamples >= kHyStartMinSamples)
    {
        m_lastRoundMinRtt = m_currRoundMinRtt;
    }
    m_currRoundMinRtt = Time::Max();
    m_rttSamples = 0;
    m_roundEnd = tcbd->m_highTxMark;
}

void
QuicCubic::OnPacketAcked(Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    NS_ASSERT_MSG(tcbd != nullptr, "tcb is not a QuicSocketState");

    tcbd->m_handshakeCount = 0;
    tcbd->m_tlpCount = 0;
    tcbd->m_rtoCount = 0;

    // No growth during recovery or when the application does not fill the window
    if (InRecovery(tcb, ackedPacket->m_packetNumber))
    {
        return;
    }

    // msquic: do not grow the window when less than half of it is being used
    if (m_bytesInFlightMax == 0)
    {
        m_bytesInFlightMax = tcbd->m_cWnd / 2;
    }
    m_bytesInFlightMax =
        std::max<uint32_t>(m_bytesInFlightMax,
                           tcbd->m_bytesInFlight.Get() + ackedPacket->m_packet->GetSize());
    if (2 * m_bytesInFlightMax <= tcbd->m_cWnd)
    {
        return;
    }

    const double mss = tcbd->m_segmentSize;
    const double acked = ackedPacket->m_packet->GetSize();
    double cwnd = tcbd->m_cWnd;

    HyStartOnAck(tcbd, ackedPacket->m_packetNumber);

    if (tcbd->m_cWnd < tcbd->m_ssThresh)
    {
        // Slow start; HyStart++ conservative slow start grows more slowly
        double growth = acked;
        if (m_hyState == HS_ACTIVE)
        {
            growth /= kHyStartCssGrowthDivisor;
        }
        cwnd += growth;
        if (cwnd >= tcbd->m_ssThresh)
        {
            cwnd = std::max<double>(tcbd->m_ssThresh, cwnd);
        }
        tcbd->m_cWnd = (uint32_t)cwnd;
        return;
    }

    // Congestion avoidance (CUBIC with Reno-friendly region)
    Time now = Simulator::Now();
    if (!m_epochStarted)
    {
        m_epochStarted = true;
        m_congAvoidStart = now;
        if (m_windowMax < cwnd)
        {
            m_windowMax = cwnd;
            m_k = 0;
        }
        else
        {
            m_k = std::cbrt((m_windowMax - cwnd) / mss / m_c);
        }
        m_aimdWindow = cwnd;
    }

    // RFC 9438, Section 4.2: the target is the cubic function one smoothed RTT ahead
    double t = (now - m_congAvoidStart + tcbd->m_smoothedRtt).GetSeconds();
    double dt = t - m_k;
    double cubicWindow = m_c * dt * dt * dt * mss + m_windowMax;

    // Reno-friendly estimate (RFC 9438 s4.3)
    // alpha_cubic is 1 once the estimate has caught up with W_max (RFC 9438, Section 4.3)
    double alpha = (m_aimdWindow < m_windowMax) ? 3.0 * (1.0 - m_beta) / (1.0 + m_beta) : 1.0;
    m_aimdWindow += alpha * acked * mss / cwnd;

    if (cubicWindow < m_aimdWindow)
    {
        cwnd = std::max(cwnd, m_aimdWindow);
    }
    else
    {
        // grow towards the cubic target, at most half of the acknowledged bytes
        double increment = (cubicWindow - cwnd) * mss / cwnd;
        increment = std::min(increment, acked / 2.0);
        cwnd += std::max(increment, 0.0);
    }
    tcbd->m_cWnd = (uint32_t)cwnd;
}

void
QuicCubic::OnCongestionEvent(Ptr<QuicSocketState> tcbd)
{
    m_saved.valid = true;
    m_saved.cwnd = tcbd->m_cWnd;
    m_saved.ssThresh = tcbd->m_ssThresh;
    m_saved.windowMax = m_windowMax;
    m_saved.windowLastMax = m_windowLastMax;
    m_saved.aimdWindow = m_aimdWindow;
    m_saved.bytesInFlightMax = m_bytesInFlightMax;
    m_saved.epochStarted = m_epochStarted;
    m_saved.congAvoidStart = m_congAvoidStart;
    m_saved.k = m_k;
    m_saved.endOfRecovery = tcbd->m_endOfRecovery;
    double cwnd = tcbd->m_cWnd;
    m_windowMax = cwnd;
    // fast convergence (RFC 9438 s4.7)
    if (m_windowLastMax > m_windowMax)
    {
        m_windowLastMax = m_windowMax;
        m_windowMax = m_windowMax * (1.0 + m_beta) / 2.0;
    }
    else
    {
        m_windowLastMax = m_windowMax;
    }
    cwnd = std::max<double>(cwnd * m_beta, tcbd->m_kMinimumWindow);
    tcbd->m_cWnd = (uint32_t)cwnd;
    tcbd->m_ssThresh = tcbd->m_cWnd;
    m_aimdWindow = cwnd;
    m_bytesInFlightMax = tcbd->m_cWnd / 2;
    m_epochStarted = false;
    m_hyState = HS_NOT_STARTED;
    m_roundEndSet = false;
    NS_LOG_INFO("CUBIC congestion event: cwnd " << tcbd->m_cWnd << " Wmax " << m_windowMax);
}

void
QuicCubic::OnSpuriousLoss(Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    if (tcbd == nullptr || !m_saved.valid || packetNumber > tcbd->m_endOfRecovery)
    {
        return;
    }
    // The congestion event was caused by reordering, not loss: undo the reduction
    tcbd->m_cWnd = std::max<uint32_t>(tcbd->m_cWnd.Get(), m_saved.cwnd);
    tcbd->m_ssThresh = m_saved.ssThresh;
    m_windowMax = m_saved.windowMax;
    m_windowLastMax = m_saved.windowLastMax;
    m_aimdWindow = m_saved.aimdWindow;
    m_bytesInFlightMax = m_saved.bytesInFlightMax;
    m_epochStarted = m_saved.epochStarted;
    m_congAvoidStart = m_saved.congAvoidStart;
    m_k = m_saved.k;
    tcbd->m_endOfRecovery = m_saved.endOfRecovery;
    m_saved.valid = false;
    NS_LOG_INFO("Spurious congestion event undone: cwnd " << tcbd->m_cWnd);
}

void
QuicCubic::OnPathChange(Ptr<TcpSocketState> tcb)
{
    // msquic CubicCongestionControlReset(FullReset = FALSE)
    QuicCongestionOps::OnPathChange(tcb);
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    if (tcbd == nullptr)
    {
        return;
    }
    m_saved.valid = false;
    m_windowMax = 0;
    m_windowLastMax = 0;
    m_aimdWindow = tcbd->m_cWnd;
    m_bytesInFlightMax = tcbd->m_cWnd / 2;
    m_k = 0;
    m_epochStarted = false;
    m_hyState = HS_NOT_STARTED;
    m_roundEndSet = false;
}

void
QuicCubic::OnPersistentCongestion(Ptr<QuicSocketState> tcbd)
{
    // msquic CubicCongestionControlOnCongestionEvent(IsPersistentCongestion): the window prior to
    // the event (already scaled by BETA by OnCongestionEvent) becomes ssthresh/Wmax; cwnd = 2
    // packets
    m_saved.valid = false;
    double reduced = tcbd->m_cWnd;
    tcbd->m_cWnd = tcbd->m_kMinimumWindow;
    tcbd->m_ssThresh = (uint32_t)reduced;
    m_windowMax = reduced;
    m_windowLastMax = reduced;
    m_aimdWindow = reduced;
    m_bytesInFlightMax = tcbd->m_cWnd / 2;
    m_k = 0;
    m_epochStarted = false;
    m_hyState = HS_NOT_STARTED;
    m_roundEndSet = false;
}

void
QuicCubic::OnRetransmissionTimeoutVerified(Ptr<TcpSocketState> tcb)
{
    // A PTO is not a congestion signal in QUIC (RFC 9002 s6.2)
    NS_LOG_FUNCTION(this);
}

void
QuicCubic::UpdatePacing(Ptr<QuicSocketState> tcbd)
{
    if (!m_pacingEnabled)
    {
        return;
    }
    tcbd->m_pacing = true;
    tcbd->m_maxPacingRate = DataRate("100Gbps");
    if (tcbd->m_smoothedRtt <= Seconds(0))
    {
        tcbd->m_pacingRate = DataRate("100Gbps");
        return;
    }
    // msquic: pace at 2 x cwnd / RTT in slow start and 1.25 x cwnd / RTT afterwards
    double gain = (tcbd->m_cWnd < tcbd->m_ssThresh) ? 2.0 : 1.25;
    double bps = gain * tcbd->m_cWnd * 8.0 / tcbd->m_smoothedRtt.GetSeconds();
    tcbd->m_pacingRate = DataRate(std::max(bps, 1e5));
}

void
QuicCubic::OnAckReceived(Ptr<TcpSocketState> tcb,
                         QuicSubheader& ack,
                         std::vector<Ptr<QuicSocketTxItem>> newAcks,
                         const struct RateSample* rs)
{
    QuicCongestionOps::OnAckReceived(tcb, ack, newAcks, rs);
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    UpdatePacing(tcbd);
}

} // namespace ns3
