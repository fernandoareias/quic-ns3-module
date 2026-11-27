/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-bbr-v3.h"

#include "quic-socket-base.h"
#include "quic-socket-tx-buffer.h"

#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <cmath>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicBbrV3");
NS_OBJECT_ENSURE_REGISTERED(QuicBbrV3);

namespace
{

/** @return the bytes a rate carries in a time. */
uint64_t
BytesIn(DataRate rate, Time t)
{
    return static_cast<uint64_t>(static_cast<double>(rate.GetBitRate()) / 8.0 * t.GetSeconds());
}

} // namespace

TypeId
QuicBbrV3::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::QuicBbrV3")
            .SetParent<QuicCongestionOps>()
            .AddConstructor<QuicBbrV3>()
            .SetGroupName("Internet")
            .AddAttribute("LossThresh",
                          "Loss rate of a round above which a probe has gone too far (BBR.LossThresh)",
                          DoubleValue(0.02),
                          MakeDoubleAccessor(&QuicBbrV3::m_lossThresh),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("Beta",
                          "Multiplicative decrease of the bounds on a loss (BBR.Beta)",
                          DoubleValue(0.7),
                          MakeDoubleAccessor(&QuicBbrV3::m_beta),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("Headroom",
                          "Fraction of inflight_longterm left free in the cruise phase "
                          "(BBR.Headroom)",
                          DoubleValue(0.15),
                          MakeDoubleAccessor(&QuicBbrV3::m_headroom),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("ProbeRttDuration",
                          "Time spent in ProbeRTT with a small window",
                          TimeValue(MilliSeconds(200)),
                          MakeTimeAccessor(&QuicBbrV3::m_probeRttDuration),
                          MakeTimeChecker())
            .AddTraceSource("BbrState",
                            "State of the BBR version 3 machine (see QuicBbrV3::BbrV3Mode)",
                            MakeTraceSourceAccessor(&QuicBbrV3::m_modeTrace),
                            "ns3::TracedValueCallback::Uint8");
    return tid;
}

const char*
QuicBbrV3::ModeName(BbrV3Mode mode)
{
    static const char* const names[] = {"STARTUP",
                                        "DRAIN",
                                        "PROBE_BW_DOWN",
                                        "PROBE_BW_CRUISE",
                                        "PROBE_BW_REFILL",
                                        "PROBE_BW_UP",
                                        "PROBE_RTT"};
    return names[mode];
}

QuicBbrV3::QuicBbrV3()
    : QuicCongestionOps()
{
    NS_LOG_FUNCTION(this);
    m_rng = CreateObject<UniformRandomVariable>();
}

QuicBbrV3::QuicBbrV3(const QuicBbrV3& other)
    : QuicCongestionOps(other),
      m_lossThresh(other.m_lossThresh),
      m_beta(other.m_beta),
      m_headroom(other.m_headroom),
      m_probeRttDuration(other.m_probeRttDuration)
{
    NS_LOG_FUNCTION(this);
    // a copy starts its own model: the connection it serves is a different one
    m_rng = CreateObject<UniformRandomVariable>();
}

int64_t
QuicBbrV3::AssignStreams(int64_t stream)
{
    m_rng->SetStream(stream);
    return 1;
}

std::string
QuicBbrV3::GetName() const
{
    return "QuicBbrV3";
}

bool
QuicBbrV3::UsesPacingRate() const
{
    return true;
}

Ptr<TcpCongestionOps>
QuicBbrV3::Fork()
{
    return CopyObject<QuicBbrV3>(this);
}

void
QuicBbrV3::CongestionStateSet(Ptr<TcpSocketState> tcb,
                              const TcpSocketState::TcpCongState_t newState)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    NS_ASSERT_MSG(tcbd, "tcb is not a QuicSocketState");
    if (newState == TcpSocketState::CA_OPEN && !m_initialized)
    {
        m_initialized = true;
        m_minPipeCwnd = 4 * tcbd->m_segmentSize;
        m_minRttStamp = Simulator::Now();
        m_priorCwnd = tcbd->m_initialCWnd;
        for (auto& bw : m_bwFilter)
        {
            bw = DataRate(0);
        }
        m_bwLatest = DataRate(0);
        m_fullBw = DataRate(0);
        if (!tcbd->m_pacing)
        {
            tcbd->m_pacing = true;
        }
        EnterStartup();
        // draft, Section 5.6.2: the first pacing rate is the initial window over the first RTT
        // estimate, with the startup gain
        Time rtt = tcbd->m_smoothedRtt.IsStrictlyPositive() ? tcbd->m_smoothedRtt
                                                            : tcbd->m_kDefaultInitialRtt;
        if (!rtt.IsStrictlyPositive())
        {
            rtt = MilliSeconds(1);
        }
        tcbd->m_pacingRate = DataRate(m_startupPacingGain * tcbd->m_initialCWnd * 8 / rtt.GetSeconds());
    }
}

void
QuicBbrV3::OnPacketSent(Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber, bool)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    NS_ASSERT_MSG(tcbd, "tcb is not a QuicSocketState");
    tcbd->m_timeOfLastSentPacket = Now();
    tcbd->m_highTxMark = packetNumber;
}

void
QuicBbrV3::OnPacketAcked(Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem>)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    NS_ASSERT_MSG(tcbd, "tcb is not a QuicSocketState");
    tcbd->m_handshakeCount = 0;
    tcbd->m_tlpCount = 0;
    tcbd->m_rtoCount = 0;
}

uint32_t
QuicBbrV3::GetSsThresh(Ptr<const TcpSocketState> tcb, uint32_t)
{
    return tcb->m_initialSsThresh;
}

void
QuicBbrV3::IncreaseWindow(Ptr<TcpSocketState>, uint32_t)
{
}

void
QuicBbrV3::OnPacketsLost(Ptr<TcpSocketState> tcb, std::vector<Ptr<QuicSocketTxItem>> lostPackets)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    NS_ASSERT_MSG(tcbd, "tcb is not a QuicSocketState");
    if (lostPackets.empty())
    {
        return;
    }
    for (const auto& item : lostPackets)
    {
        m_lostSinceAck += item->m_packet->GetSize() + item->m_overhead;
    }
    // draft, Section 5.5.2: each loss event of a round counts, and the round has a loss
    m_isLossInRound = true;
    ++m_lossEventsInRound;
    auto largest = *(lostPackets.end() - 1);
    if (!InRecovery(tcb, largest->m_packetNumber))
    {
        tcbd->m_endOfRecovery = tcbd->m_highTxMark;
    }
}

void
QuicBbrV3::OnAckReceived(Ptr<TcpSocketState> tcb,
                         QuicSubheader& ack,
                         std::vector<Ptr<QuicSocketTxItem>> newAcks,
                         const struct RateSample* rs)
{
    Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*>(&(*tcb));
    NS_ASSERT_MSG(tcbd, "tcb is not a QuicSocketState");
    tcbd->m_largestAckedPacket = SequenceNumber32(ack.GetLargestAcknowledged());

    // the packets are ordered from the highest number to the lowest
    Ptr<QuicSocketTxItem> lastAcked = newAcks.at(0);
    if (lastAcked->m_packetNumber == tcbd->m_largestAckedPacket && lastAcked->m_ackEliciting)
    {
        tcbd->m_lastRtt = Now() - lastAcked->m_lastSent;
        UpdateRtt(tcbd, tcbd->m_lastRtt, MicroSeconds(ack.GetAckDelay()));
    }
    uint32_t newlyAcked = 0;
    for (auto it = newAcks.rbegin(); it != newAcks.rend(); ++it)
    {
        newlyAcked += (*it)->m_packet->GetSize() + (*it)->m_overhead;
        OnPacketAcked(tcb, *it);
    }
    UpdateOnAck(tcbd, rs, newlyAcked);
}

DataRate
QuicBbrV3::MaxBw() const
{
    return std::max(m_bwFilter[0], m_bwFilter[1]);
}

DataRate
QuicBbrV3::ModelBw() const
{
    DataRate bw = MaxBw();
    if (m_bwShorttermValid)
    {
        bw = std::min(bw, m_bwShortterm);
    }
    return bw;
}

uint64_t
QuicBbrV3::BdpMultiple(double gain, uint32_t initialWindow) const
{
    if (m_minRtt == Time::Max())
    {
        return initialWindow;
    }
    return static_cast<uint64_t>(gain * static_cast<double>(BytesIn(ModelBw(), m_minRtt)));
}

uint64_t
QuicBbrV3::Inflight(double gain, const Ptr<QuicSocketState>& tcb) const
{
    uint64_t cap = BdpMultiple(gain, tcb->m_initialCWnd);
    // draft, Section 5.6.4.2: the budget for sending in bursts, and the minimum
    cap = std::max<uint64_t>(cap, 2 * tcb->m_segmentSize);
    cap = std::max<uint64_t>(cap, m_minPipeCwnd);
    if (m_mode == PROBE_BW_UP)
    {
        cap += 2 * tcb->m_segmentSize;
    }
    return cap;
}

uint64_t
QuicBbrV3::InflightWithHeadroom(const Ptr<QuicSocketState>& tcb) const
{
    if (m_inflightLongterm == UINT64_MAX)
    {
        return UINT64_MAX;
    }
    const uint64_t headroom =
        std::max<uint64_t>(tcb->m_segmentSize,
                           static_cast<uint64_t>(m_headroom * static_cast<double>(m_inflightLongterm)));
    const uint64_t bound = m_inflightLongterm > headroom ? m_inflightLongterm - headroom : 0;
    return std::max<uint64_t>(bound, m_minPipeCwnd);
}

uint64_t
QuicBbrV3::TargetInflight(const Ptr<QuicSocketState>& tcb) const
{
    return std::min<uint64_t>(BdpMultiple(1.0, tcb->m_initialCWnd), tcb->m_cWnd.Get());
}

bool
QuicBbrV3::IsInflightTooHigh(uint64_t lost, uint64_t txInFlight) const
{
    return lost > 0 && static_cast<double>(lost) > static_cast<double>(txInFlight) * m_lossThresh;
}

void
QuicBbrV3::SetMode(BbrV3Mode mode)
{
    if (m_mode != mode)
    {
        NS_LOG_INFO("BBRv3 " << ModeName(m_mode) << " -> " << ModeName(mode));
    }
    m_mode = mode;
    m_modeTrace = static_cast<uint8_t>(mode);
}

void
QuicBbrV3::UpdateOnAck(Ptr<QuicSocketState> tcb, const struct RateSample* rs, uint32_t newlyAcked)
{
    m_minPipeCwnd = 4 * tcb->m_segmentSize;
    m_lastSampleAppLimited = rs->m_isAppLimited;
    m_lastTxInFlight = rs->m_priorInFlight;

    // draft, Section 5.5.1: UpdateModelAndState
    UpdateRound(tcb, rs);
    UpdateLatestDeliverySignals(tcb, rs);
    UpdateCongestionSignals(tcb, rs);
    UpdateAckAggregation(tcb, rs, newlyAcked);
    CheckFullBwReached(rs);
    CheckStartupDone(tcb, rs);
    CheckDrainDone(tcb);
    UpdateProbeBwCyclePhase(tcb, rs);
    AdaptLongTermModel(tcb, rs, newlyAcked);
    UpdateMinRtt(tcb);
    CheckProbeRtt(tcb);
    AdvanceLatestDeliverySignals(rs);

    // draft, Section 5.5.2: UpdateControlParameters
    SetPacingRate(tcb);
    SetCwnd(tcb, newlyAcked);
    m_lostSinceAck = 0;
}

void
QuicBbrV3::UpdateRound(Ptr<QuicSocketState> tcb, const struct RateSample*)
{
    if (tcb->m_txItemDelivered >= m_nextRoundDelivered)
    {
        m_nextRoundDelivered = tcb->m_delivered;
        ++m_roundCount;
        m_roundStart = true;
        ++m_roundsSinceProbe;
    }
    else
    {
        m_roundStart = false;
    }
}

void
QuicBbrV3::UpdateMaxBw(const struct RateSample* rs)
{
    if (rs->m_deliveryRate.GetBitRate() == 0)
    {
        return;
    }
    if (rs->m_deliveryRate >= MaxBw() || !rs->m_isAppLimited)
    {
        m_bwFilter[0] = std::max(m_bwFilter[0], rs->m_deliveryRate);
    }
}

void
QuicBbrV3::AdvanceMaxBwFilter()
{
    // draft, Section 5.5.5: the filter spans two cycles of ProbeBW
    m_bwFilter[1] = m_bwFilter[0];
    m_bwFilter[0] = DataRate(0);
}

void
QuicBbrV3::UpdateLatestDeliverySignals(Ptr<QuicSocketState> tcb, const struct RateSample* rs)
{
    m_lossRoundStart = false;
    m_bwLatest = std::max(m_bwLatest, rs->m_deliveryRate);
    m_inflightLatest = std::max<uint64_t>(m_inflightLatest, rs->m_delivered);
    if (tcb->m_txItemDelivered >= m_lossRoundDelivered)
    {
        m_lossRoundDelivered = tcb->m_delivered;
        m_lossRoundStart = true;
    }
}

void
QuicBbrV3::AdvanceLatestDeliverySignals(const struct RateSample* rs)
{
    if (m_lossRoundStart)
    {
        m_bwLatest = rs->m_deliveryRate;
        m_inflightLatest = rs->m_delivered;
        m_lossEventsInRound = 0;
    }
}

void
QuicBbrV3::UpdateCongestionSignals(Ptr<QuicSocketState> tcb, const struct RateSample* rs)
{
    UpdateMaxBw(rs);
    if (m_lossRoundStart)
    {
        AdaptLowerBoundsFromCongestion(tcb);
        m_isLossInRound = false;
    }
}

void
QuicBbrV3::AdaptLowerBoundsFromCongestion(Ptr<QuicSocketState> tcb)
{
    // draft, Section 5.5.6: the lower bounds follow the losses, but not while the flow probes
    if (m_mode == STARTUP || m_mode == PROBE_BW_REFILL || m_mode == PROBE_BW_UP)
    {
        return;
    }
    if (m_isLossInRound)
    {
        if (!m_bwShorttermValid)
        {
            m_bwShortterm = MaxBw();
            m_bwShorttermValid = true;
        }
        if (m_inflightShortterm == UINT64_MAX)
        {
            m_inflightShortterm = tcb->m_cWnd.Get();
        }
        m_bwShortterm = std::max(
            m_bwLatest,
            DataRate(static_cast<uint64_t>(m_beta * static_cast<double>(m_bwShortterm.GetBitRate()))));
        m_inflightShortterm = std::max<uint64_t>(
            m_inflightLatest,
            static_cast<uint64_t>(m_beta * static_cast<double>(m_inflightShortterm)));
    }
}

void
QuicBbrV3::ResetCongestionSignals()
{
    m_isLossInRound = false;
    m_lossEventsInRound = 0;
    m_bwLatest = DataRate(0);
    m_inflightLatest = 0;
}

void
QuicBbrV3::ResetShortTermModel()
{
    m_bwShorttermValid = false;
    m_inflightShortterm = UINT64_MAX;
}

void
QuicBbrV3::UpdateAckAggregation(Ptr<QuicSocketState> tcb,
                                const struct RateSample*,
                                uint32_t newlyAcked)
{
    // draft, Section 5.5.9: the extra data acknowledged beyond what the bandwidth predicts in the
    // time since the epoch started, a maximum over the latest windows
    const Time now = Simulator::Now();
    if (!m_ackEpochStart.IsStrictlyPositive())
    {
        m_ackEpochStart = now;
        m_ackEpochAcked = 0;
    }
    uint64_t expected = BytesIn(ModelBw(), now - m_ackEpochStart);
    if (m_ackEpochAcked <= expected)
    {
        m_ackEpochAcked = 0;
        m_ackEpochStart = now;
        expected = 0;
    }
    m_ackEpochAcked += newlyAcked;
    uint64_t extra = m_ackEpochAcked > expected ? m_ackEpochAcked - expected : 0;
    extra = std::min<uint64_t>(extra, tcb->m_cWnd.Get());
    const uint64_t windowRounds = m_fullBwReached ? 10 : 1;
    if (m_roundCount >= m_extraAckedRound + windowRounds)
    {
        m_extraAckedWin = (m_extraAckedWin + 1) % 2;
        m_extraAcked[m_extraAckedWin] = 0;
        m_extraAckedRound = m_roundCount;
    }
    m_extraAcked[m_extraAckedWin] = std::max(m_extraAcked[m_extraAckedWin], extra);
}

void
QuicBbrV3::CheckFullBwReached(const struct RateSample* rs)
{
    if (m_fullBwNow || !m_roundStart || rs->m_isAppLimited)
    {
        return;
    }
    // draft, Section 5.3.1.2: the pipe is full when the delivery rate stops growing by 25% for
    // three rounds
    const double grown = 1.25 * static_cast<double>(m_fullBw.GetBitRate());
    if (static_cast<double>(rs->m_deliveryRate.GetBitRate()) >= grown)
    {
        m_fullBw = rs->m_deliveryRate;
        m_fullBwCount = 0;
        return;
    }
    ++m_fullBwCount;
    m_fullBwNow = m_fullBwCount >= 3;
    if (m_fullBwNow)
    {
        m_fullBwReached = true;
    }
}

void
QuicBbrV3::CheckStartupDone(Ptr<QuicSocketState> tcb, const struct RateSample* rs)
{
    if (m_mode != STARTUP)
    {
        return;
    }
    // draft, Section 5.3.1.3: also a loss rate above the threshold, with enough loss events in
    // the round, ends Startup
    if (!m_fullBwReached && m_lossRoundStart && m_isLossInRound &&
        m_lossEventsInRound >= m_startupFullLossCnt &&
        IsInflightTooHigh(m_lostSinceAck, rs->m_priorInFlight))
    {
        m_fullBwReached = true;
        m_inflightLongterm = std::max<uint64_t>(BdpMultiple(1.0, tcb->m_initialCWnd), m_inflightLatest);
    }
    if (m_fullBwReached)
    {
        SetMode(DRAIN);
        m_pacingGain = m_drainPacingGain;
        m_cwndGain = m_defaultCwndGain;
    }
}

void
QuicBbrV3::CheckDrainDone(Ptr<QuicSocketState> tcb)
{
    if (m_mode == DRAIN && tcb->m_bytesInFlight.Get() <= Inflight(1.0, tcb))
    {
        EnterProbeBw(tcb);
    }
}

void
QuicBbrV3::EnterStartup()
{
    SetMode(STARTUP);
    m_pacingGain = m_startupPacingGain;
    m_cwndGain = m_defaultCwndGain;
}

void
QuicBbrV3::EnterProbeBw(Ptr<QuicSocketState> tcb)
{
    m_cwndGain = m_defaultCwndGain;
    StartProbeBwDown(tcb);
}

void
QuicBbrV3::PickProbeWait()
{
    // draft, Section 5.3.3.2: a round count and a wall clock time to the next probe
    m_roundsSinceProbe = static_cast<uint32_t>(m_rng->GetInteger(0, 1));
    m_bwProbeWait = Seconds(2.0 + m_rng->GetValue(0.0, 1.0));
}

void
QuicBbrV3::StartProbeBwDown(Ptr<QuicSocketState> tcb)
{
    ResetCongestionSignals();
    m_probeUpAckedPerInc = UINT64_MAX;
    PickProbeWait();
    m_cycleStamp = Simulator::Now();
    m_isBwProbeStopping = true;
    m_nextRoundDelivered = tcb->m_delivered;
    SetMode(PROBE_BW_DOWN);
    m_pacingGain = 0.9;
    m_cwndGain = m_defaultCwndGain;
    AdvanceMaxBwFilter();
}

void
QuicBbrV3::StartProbeBwCruise()
{
    SetMode(PROBE_BW_CRUISE);
    m_pacingGain = 1.0;
    m_cwndGain = m_defaultCwndGain;
}

void
QuicBbrV3::StartProbeBwRefill(Ptr<QuicSocketState> tcb)
{
    ResetShortTermModel();
    m_bwProbeUpRounds = 0;
    m_bwProbeUpAcked = 0;
    m_prevProbePrecautionary = false;
    m_isBwProbeStopping = false;
    m_nextRoundDelivered = tcb->m_delivered;
    SetMode(PROBE_BW_REFILL);
    m_pacingGain = 1.0;
    m_cwndGain = m_defaultCwndGain;
}

void
QuicBbrV3::StartProbeBwUp(Ptr<QuicSocketState> tcb, const struct RateSample* rs)
{
    m_nextRoundDelivered = tcb->m_delivered;
    // the plateau test starts again from the rate of this probe
    m_fullBwNow = false;
    m_fullBwCount = 0;
    m_fullBw = rs->m_deliveryRate;
    m_cycleStamp = Simulator::Now();
    SetMode(PROBE_BW_UP);
    m_pacingGain = 1.25;
    m_cwndGain = 2.25;
    RaiseInflightLongtermSlope(tcb);
}

void
QuicBbrV3::RaiseInflightLongtermSlope(Ptr<QuicSocketState> tcb)
{
    const uint64_t growth = 1ULL << m_bwProbeUpRounds;
    m_bwProbeUpRounds = std::min<uint32_t>(m_bwProbeUpRounds + 1, 30);
    m_probeUpAckedPerInc = std::max<uint64_t>(tcb->m_cWnd.Get() / growth, tcb->m_segmentSize);
}

bool
QuicBbrV3::IsRenoCoexistenceProbeTime(Ptr<QuicSocketState> tcb)
{
    const uint64_t packets = TargetInflight(tcb) / std::max<uint32_t>(tcb->m_segmentSize, 1);
    const uint64_t rounds = std::min<uint64_t>(packets, 63);
    return m_roundsSinceProbe >= rounds;
}

bool
QuicBbrV3::IsTimeToProbeBw(Ptr<QuicSocketState> tcb)
{
    if (Simulator::Now() - m_cycleStamp > m_bwProbeWait || IsRenoCoexistenceProbeTime(tcb))
    {
        StartProbeBwRefill(tcb);
        return true;
    }
    return false;
}

bool
QuicBbrV3::IsTimeToCruise(Ptr<QuicSocketState> tcb)
{
    const uint64_t inflight = tcb->m_bytesInFlight.Get();
    return inflight <= InflightWithHeadroom(tcb) && inflight <= Inflight(1.0, tcb);
}

bool
QuicBbrV3::IsTimeToGoDown(Ptr<QuicSocketState> tcb)
{
    const bool cwndLimited = tcb->m_bytesInFlight.Get() >= tcb->m_cWnd.Get();
    if (cwndLimited && tcb->m_cWnd.Get() >= m_inflightLongterm)
    {
        // the long-term bound is what limits the probe: look for more room
        m_fullBwNow = false;
        m_fullBwCount = 0;
        return false;
    }
    return m_fullBwNow;
}

void
QuicBbrV3::UpdateProbeBwCyclePhase(Ptr<QuicSocketState> tcb, const struct RateSample* rs)
{
    if (!m_fullBwReached)
    {
        return;
    }
    switch (m_mode)
    {
    case PROBE_BW_DOWN:
        if (IsTimeToProbeBw(tcb))
        {
            return;
        }
        if (IsTimeToCruise(tcb))
        {
            StartProbeBwCruise();
        }
        break;
    case PROBE_BW_CRUISE:
        IsTimeToProbeBw(tcb);
        break;
    case PROBE_BW_REFILL:
        // draft, Section 5.3.3.4: one round of REFILL, then the probe up
        if (m_roundStart)
        {
            m_checkProbeLoss = true;
            StartProbeBwUp(tcb, rs);
        }
        break;
    case PROBE_BW_UP:
        if (m_prevProbeTooHigh && tcb->m_bytesInFlight.Get() >= m_inflightLongterm)
        {
            m_prevProbePrecautionary = true;
            StartProbeBwDown(tcb);
        }
        else if (IsTimeToGoDown(tcb))
        {
            StartProbeBwDown(tcb);
        }
        break;
    default:
        break;
    }
}

void
QuicBbrV3::HandleInflightTooHigh(Ptr<QuicSocketState> tcb, const struct RateSample* rs)
{
    m_prevProbeTooHigh = true;
    m_checkProbeLoss = false;
    if (!rs->m_isAppLimited)
    {
        m_inflightLongterm = std::max<uint64_t>(
            m_lastTxInFlight,
            static_cast<uint64_t>(static_cast<double>(TargetInflight(tcb)) * m_beta));
    }
    if (m_mode == PROBE_BW_UP)
    {
        StartProbeBwDown(tcb);
    }
}

void
QuicBbrV3::ProbeInflightLongtermUpward(Ptr<QuicSocketState> tcb, uint32_t newlyAcked)
{
    if (tcb->m_bytesInFlight.Get() < tcb->m_cWnd.Get() || tcb->m_cWnd.Get() < m_inflightLongterm)
    {
        return; // only a window that limits the flow, at the bound, probes it upward
    }
    m_bwProbeUpAcked += newlyAcked;
    if (m_probeUpAckedPerInc != UINT64_MAX && m_bwProbeUpAcked >= m_probeUpAckedPerInc)
    {
        const uint64_t delta = m_bwProbeUpAcked / m_probeUpAckedPerInc;
        m_bwProbeUpAcked -= delta * m_probeUpAckedPerInc;
        if (m_inflightLongterm != UINT64_MAX)
        {
            m_inflightLongterm += delta * tcb->m_segmentSize;
        }
    }
    if (m_roundStart)
    {
        RaiseInflightLongtermSlope(tcb);
    }
}

void
QuicBbrV3::AdaptLongTermModel(Ptr<QuicSocketState> tcb,
                              const struct RateSample* rs,
                              uint32_t newlyAcked)
{
    const bool probing = m_mode == PROBE_BW_REFILL || m_mode == PROBE_BW_UP;
    if (m_mode == STARTUP || m_mode == DRAIN || m_mode == PROBE_RTT)
    {
        return;
    }
    if (m_isBwProbeStopping && m_roundStart)
    {
        m_checkProbeLoss = false;
        m_isBwProbeStopping = false;
        if (m_prevProbePrecautionary && !m_prevProbeTooHigh)
        {
            StartProbeBwRefill(tcb);
            return;
        }
        m_prevProbeTooHigh = false;
    }
    if (!probing && !m_checkProbeLoss)
    {
        return;
    }
    if (m_checkProbeLoss && IsInflightTooHigh(m_lostSinceAck, rs->m_priorInFlight))
    {
        HandleInflightTooHigh(tcb, rs);
        return;
    }
    // the inflight is not too high: the bound rises to what was sent without loss
    if (m_inflightLongterm != UINT64_MAX && rs->m_priorInFlight > m_inflightLongterm)
    {
        m_inflightLongterm = rs->m_priorInFlight;
    }
    if (m_mode == PROBE_BW_UP)
    {
        ProbeInflightLongtermUpward(tcb, newlyAcked);
    }
}

void
QuicBbrV3::UpdateMinRtt(Ptr<QuicSocketState> tcb)
{
    const Time now = Simulator::Now();
    m_minRttExpired = now > m_minRttStamp + m_minRttFilterLen;
    if (m_minRttExpired)
    {
        m_probeRttCwnd = BdpMultiple(m_probeRttCwndGain, tcb->m_initialCWnd);
    }
    const Time sample = tcb->m_latestRtt;
    if (sample.IsStrictlyPositive() && (sample < m_minRtt || m_minRttExpired))
    {
        m_minRtt = sample;
        m_minRttStamp = now;
    }
}

void
QuicBbrV3::CheckProbeRtt(Ptr<QuicSocketState> tcb)
{
    if (m_mode != PROBE_RTT && m_minRttExpired && m_fullBwReached)
    {
        SaveCwnd(tcb);
        SetMode(PROBE_RTT);
        m_pacingGain = 1.0;
        m_cwndGain = m_probeRttCwndGain;
        m_probeRttDoneStamp = Seconds(0);
        m_probeRttRoundDone = false;
        m_isBwProbeStopping = true;
        m_nextRoundDelivered = tcb->m_delivered;
    }
    if (m_mode == PROBE_RTT)
    {
        HandleProbeRtt(tcb);
    }
}

void
QuicBbrV3::HandleProbeRtt(Ptr<QuicSocketState> tcb)
{
    // the flow does not use all it could while it waits for the pipe to drain
    tcb->m_appLimitedUntil = std::max<uint64_t>(tcb->m_delivered + tcb->m_bytesInFlight.Get(), 1);
    const uint64_t target = std::max<uint64_t>(std::min<uint64_t>(BdpMultiple(m_probeRttCwndGain,
                                                                                tcb->m_initialCWnd),
                                                                  m_probeRttCwnd ? m_probeRttCwnd
                                                                                 : UINT64_MAX),
                                               m_minPipeCwnd);
    if (!m_probeRttDoneStamp.IsStrictlyPositive() && tcb->m_bytesInFlight.Get() <= target)
    {
        m_probeRttDoneStamp = Simulator::Now() + m_probeRttDuration;
        m_probeRttRoundDone = false;
        m_nextRoundDelivered = tcb->m_delivered;
    }
    else if (m_probeRttDoneStamp.IsStrictlyPositive())
    {
        if (m_roundStart)
        {
            m_probeRttRoundDone = true;
        }
        if (m_probeRttRoundDone)
        {
            CheckProbeRttDone(tcb);
        }
    }
}

void
QuicBbrV3::CheckProbeRttDone(Ptr<QuicSocketState> tcb)
{
    if (m_probeRttDoneStamp.IsStrictlyPositive() && Simulator::Now() > m_probeRttDoneStamp)
    {
        m_minRttStamp = Simulator::Now();
        RestoreCwnd(tcb);
        ExitProbeRtt(tcb);
    }
}

void
QuicBbrV3::ExitProbeRtt(Ptr<QuicSocketState> tcb)
{
    ResetShortTermModel();
    if (m_fullBwReached)
    {
        StartProbeBwDown(tcb);
        StartProbeBwCruise();
    }
    else
    {
        EnterStartup();
    }
}

void
QuicBbrV3::SaveCwnd(Ptr<QuicSocketState> tcb)
{
    if (m_mode != PROBE_RTT)
    {
        m_priorCwnd = tcb->m_cWnd.Get();
    }
    else
    {
        m_priorCwnd = std::max<uint64_t>(m_priorCwnd, tcb->m_cWnd.Get());
    }
}

void
QuicBbrV3::RestoreCwnd(Ptr<QuicSocketState> tcb)
{
    tcb->m_cWnd = static_cast<uint32_t>(std::max<uint64_t>(tcb->m_cWnd.Get(), m_priorCwnd));
}

void
QuicBbrV3::SetPacingRate(Ptr<QuicSocketState> tcb)
{
    // draft, Section 5.6.2: a margin of 1% under the estimate
    DataRate rate(static_cast<uint64_t>(m_pacingGain * static_cast<double>(ModelBw().GetBitRate()) *
                                        99.0 / 100.0));
    rate = std::min(rate, tcb->m_maxPacingRate);
    if (m_fullBwReached || rate > tcb->m_pacingRate)
    {
        tcb->m_pacingRate = rate;
    }
}

uint64_t
QuicBbrV3::BoundCwndForModel(Ptr<QuicSocketState> tcb, uint64_t cwnd) const
{
    uint64_t cap = UINT64_MAX;
    if (m_mode == PROBE_BW_DOWN || m_mode == PROBE_BW_REFILL || m_mode == PROBE_BW_UP)
    {
        cap = m_inflightLongterm;
    }
    else if (m_mode == PROBE_RTT || m_mode == PROBE_BW_CRUISE)
    {
        cap = InflightWithHeadroom(tcb);
    }
    cap = std::min(cap, m_inflightShortterm);
    if (cap != UINT64_MAX)
    {
        cwnd = std::min(cwnd, std::max<uint64_t>(cap, m_minPipeCwnd));
    }
    return cwnd;
}

void
QuicBbrV3::SetCwnd(Ptr<QuicSocketState> tcb, uint32_t newlyAcked)
{
    // draft, Section 5.6.4: grow with the data acknowledged up to what the model asks for
    const uint64_t extra = std::max(m_extraAcked[0], m_extraAcked[1]);
    uint64_t maxInflight = BdpMultiple(m_cwndGain, tcb->m_initialCWnd) + extra;
    maxInflight = std::max<uint64_t>(maxInflight, 2 * tcb->m_segmentSize);
    maxInflight = std::max<uint64_t>(maxInflight, m_minPipeCwnd);
    if (m_mode == PROBE_BW_UP)
    {
        maxInflight += 2 * tcb->m_segmentSize;
    }
    uint64_t cwnd = tcb->m_cWnd.Get();
    if (m_fullBwReached)
    {
        cwnd = std::min<uint64_t>(cwnd + newlyAcked, maxInflight);
    }
    else if (cwnd < maxInflight || tcb->m_delivered < tcb->m_initialCWnd)
    {
        cwnd += newlyAcked;
    }
    cwnd = std::max<uint64_t>(cwnd, m_minPipeCwnd);
    if (m_mode == PROBE_RTT)
    {
        cwnd = std::min<uint64_t>(cwnd, m_probeRttCwnd ? std::max<uint64_t>(m_probeRttCwnd, m_minPipeCwnd)
                                                       : cwnd);
    }
    cwnd = BoundCwndForModel(tcb, cwnd);
    tcb->m_cWnd = static_cast<uint32_t>(std::min<uint64_t>(cwnd, UINT32_MAX));
}

} // namespace ns3
