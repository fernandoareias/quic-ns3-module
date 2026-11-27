/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_BBR_V3_H
#define QUIC_BBR_V3_H

#include "quic-congestion-ops.h"

#include "ns3/data-rate.h"
#include "ns3/nstime.h"
#include "ns3/random-variable-stream.h"
#include "ns3/traced-value.h"

#include <cstdint>

namespace ns3
{

/**
 * @ingroup quic
 *
 * BBR version 3, as draft-ietf-ccwg-bbr-07 describes it. It estimates the bottleneck bandwidth and
 * the minimum round trip time and paces at the bandwidth, as BBR version 1 does, and adds what the
 * second and third versions learned: the states ProbeBW_DOWN, ProbeBW_CRUISE, ProbeBW_REFILL and
 * ProbeBW_UP, a long-term bound on the data in flight (inflight_longterm) that a probe that
 * causes a loss rate above 2% lowers, short-term bounds (bw_shortterm and inflight_shortterm) that
 * follow the losses of the current rounds, a headroom of 15% in the cruise phase, and a maximum
 * bandwidth filter of two probing cycles.
 *
 * It is a separate controller from QuicBbr, which stays as the port of BBR version 1.
 */
class QuicBbrV3 : public QuicCongestionOps
{
  public:
    /** The states of the controller. */
    enum BbrV3Mode
    {
        STARTUP,
        DRAIN,
        PROBE_BW_DOWN,
        PROBE_BW_CRUISE,
        PROBE_BW_REFILL,
        PROBE_BW_UP,
        PROBE_RTT
    };

    /**
     * Get the type ID.
     *
     * @return the object TypeId.
     */
    static TypeId GetTypeId();

    QuicBbrV3();
    QuicBbrV3(const QuicBbrV3& other);

    /** @return the current state. */
    BbrV3Mode GetMode() const
    {
        return m_mode;
    }

    /** @return the name of a state. */
    static const char* ModeName(BbrV3Mode mode);

    // QuicCongestionOps and TcpCongestionOps
    int64_t AssignStreams(int64_t stream);
    std::string GetName() const override;
    bool UsesPacingRate() const override;
    void CongestionStateSet(Ptr<TcpSocketState> tcb,
                            const TcpSocketState::TcpCongState_t newState) override;
    void OnPacketSent(Ptr<TcpSocketState> tcb,
                      SequenceNumber32 packetNumber,
                      bool isAckOnly) override;
    void OnAckReceived(Ptr<TcpSocketState> tcb,
                       QuicSubheader& ack,
                       std::vector<Ptr<QuicSocketTxItem>> newAcks,
                       const struct RateSample* rs) override;
    void OnPacketsLost(Ptr<TcpSocketState> tcb,
                       std::vector<Ptr<QuicSocketTxItem>> lostPackets) override;
    uint32_t GetSsThresh(Ptr<const TcpSocketState> tcb, uint32_t bytesInFlight) override;
    void IncreaseWindow(Ptr<TcpSocketState> tcb, uint32_t segmentsAcked) override;
    Ptr<TcpCongestionOps> Fork() override;

  protected:
    void OnPacketAcked(Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket) override;

  private:
    /** The model of the path and the control, one update for each ACK (draft, Section 5.5). */
    void UpdateOnAck(Ptr<QuicSocketState> tcb, const struct RateSample* rs, uint32_t newlyAcked);

    /** @return the maximum bandwidth of the filter. */
    DataRate MaxBw() const;
    /** @return the bandwidth the model uses: the maximum, bounded by the short-term bound. */
    DataRate ModelBw() const;
    /** @return gain times the bandwidth-delay product, in bytes. */
    uint64_t BdpMultiple(double gain, uint32_t initialWindow) const;
    /** @return the data in flight that a gain asks for, with the quantization budget. */
    uint64_t Inflight(double gain, const Ptr<QuicSocketState>& tcb) const;
    /** @return inflight_longterm less the headroom, or infinity. */
    uint64_t InflightWithHeadroom(const Ptr<QuicSocketState>& tcb) const;
    /** @return the target of the data in flight for a probe, in bytes. */
    uint64_t TargetInflight(const Ptr<QuicSocketState>& tcb) const;
    /** @return true when the loss of the sample is above the threshold. */
    bool IsInflightTooHigh(uint64_t lost, uint64_t txInFlight) const;

    void UpdateRound(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    void UpdateMaxBw(const struct RateSample* rs);
    void AdvanceMaxBwFilter();
    void UpdateLatestDeliverySignals(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    void AdvanceLatestDeliverySignals(const struct RateSample* rs);
    void UpdateCongestionSignals(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    void AdaptLowerBoundsFromCongestion(Ptr<QuicSocketState> tcb);
    void ResetCongestionSignals();
    void ResetShortTermModel();
    void UpdateAckAggregation(Ptr<QuicSocketState> tcb,
                              const struct RateSample* rs,
                              uint32_t newlyAcked);
    void CheckFullBwReached(const struct RateSample* rs);
    void CheckStartupDone(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    void CheckDrainDone(Ptr<QuicSocketState> tcb);
    void UpdateProbeBwCyclePhase(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    void AdaptLongTermModel(Ptr<QuicSocketState> tcb,
                            const struct RateSample* rs,
                            uint32_t newlyAcked);
    void HandleInflightTooHigh(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    void ProbeInflightLongtermUpward(Ptr<QuicSocketState> tcb, uint32_t newlyAcked);
    void RaiseInflightLongtermSlope(Ptr<QuicSocketState> tcb);
    void UpdateMinRtt(Ptr<QuicSocketState> tcb);
    void CheckProbeRtt(Ptr<QuicSocketState> tcb);
    void HandleProbeRtt(Ptr<QuicSocketState> tcb);
    void CheckProbeRttDone(Ptr<QuicSocketState> tcb);
    void ExitProbeRtt(Ptr<QuicSocketState> tcb);
    void EnterStartup();
    void EnterProbeBw(Ptr<QuicSocketState> tcb);
    void StartProbeBwDown(Ptr<QuicSocketState> tcb);
    void StartProbeBwCruise();
    void StartProbeBwRefill(Ptr<QuicSocketState> tcb);
    void StartProbeBwUp(Ptr<QuicSocketState> tcb, const struct RateSample* rs);
    bool IsTimeToProbeBw(Ptr<QuicSocketState> tcb);
    bool IsTimeToCruise(Ptr<QuicSocketState> tcb);
    bool IsTimeToGoDown(Ptr<QuicSocketState> tcb);
    bool IsRenoCoexistenceProbeTime(Ptr<QuicSocketState> tcb);
    void PickProbeWait();
    void SetMode(BbrV3Mode mode);
    void SetPacingRate(Ptr<QuicSocketState> tcb);
    void SetCwnd(Ptr<QuicSocketState> tcb, uint32_t newlyAcked);
    uint64_t BoundCwndForModel(Ptr<QuicSocketState> tcb, uint64_t cwnd) const;
    void SaveCwnd(Ptr<QuicSocketState> tcb);
    void RestoreCwnd(Ptr<QuicSocketState> tcb);

    // constants (draft, Section 2)
    double m_lossThresh{0.02};         //!< BBR.LossThresh
    double m_beta{0.7};                //!< BBR.Beta
    double m_headroom{0.15};           //!< BBR.Headroom
    uint32_t m_startupFullLossCnt{6};  //!< BBR.StartupFullLossCnt
    double m_startupPacingGain{2.77};  //!< 4 * ln (2)
    double m_drainPacingGain{0.5};     //!< BBR.DrainPacingGain
    double m_defaultCwndGain{2.0};     //!< BBR.DefaultCwndGain
    Time m_minRttFilterLen{Seconds(10)}; //!< BBR.MinRTTFilterLen
    Time m_probeRttDuration{MilliSeconds(200)}; //!< BBR.ProbeRTTDuration
    double m_probeRttCwndGain{0.5};    //!< BBR.ProbeRTTCwndGain

    // state of the machine
    BbrV3Mode m_mode{STARTUP};         //!< current state
    TracedValue<uint8_t> m_modeTrace;  //!< trace of the state (as a number)
    bool m_initialized{false};         //!< the model has its first values
    double m_pacingGain{2.77};         //!< current pacing gain
    double m_cwndGain{2.0};            //!< current cwnd gain

    // bandwidth and round trip time
    DataRate m_bwFilter[2];            //!< maximum bandwidth of the current and previous cycles
    DataRate m_bwShortterm;            //!< short-term lower bound of the bandwidth
    bool m_bwShorttermValid{false};    //!< m_bwShortterm is set (it is infinite otherwise)
    Time m_minRtt{Time::Max()};        //!< minimum round trip time of the last 10 seconds
    Time m_minRttStamp;                //!< when it was measured
    bool m_minRttExpired{false};       //!< the filter window passed

    // rounds
    uint64_t m_roundCount{0};          //!< packet-timed rounds
    uint64_t m_nextRoundDelivered{0};  //!< delivered count that ends the round
    bool m_roundStart{false};          //!< a round started with this ACK
    uint64_t m_lossRoundDelivered{0};  //!< delivered count that ends the loss round
    bool m_lossRoundStart{false};      //!< a loss round started with this ACK
    bool m_isLossInRound{false};       //!< a loss happened in the loss round
    uint32_t m_lossEventsInRound{0};   //!< loss events in the loss round

    // delivery signals of the latest rounds
    DataRate m_bwLatest;               //!< maximum delivery rate in the loss round
    uint64_t m_inflightLatest{0};      //!< maximum data delivered in the loss round, bytes
    uint64_t m_inflightShortterm{UINT64_MAX}; //!< short-term bound of the data in flight
    uint64_t m_inflightLongterm{UINT64_MAX};  //!< long-term bound of the data in flight
    uint64_t m_lostSinceAck{0};        //!< bytes declared lost since the last ACK was processed

    // full pipe
    DataRate m_fullBw;                 //!< bandwidth at the start of the plateau
    uint32_t m_fullBwCount{0};         //!< rounds without growth of 25%
    bool m_fullBwNow{false};           //!< the pipe looks full in this round
    bool m_fullBwReached{false};       //!< the pipe is full

    // ProbeBW
    Time m_cycleStamp;                 //!< start of the cycle
    Time m_bwProbeWait;                //!< time to the next probe
    uint32_t m_roundsSinceProbe{0};    //!< rounds since the last ProbeBW_UP
    uint32_t m_bwProbeUpRounds{0};     //!< rounds of the probe up
    uint64_t m_bwProbeUpAcked{0};      //!< bytes acknowledged since the last increase
    uint64_t m_probeUpAckedPerInc{UINT64_MAX}; //!< bytes that raise inflight_longterm by one MSS
    bool m_prevProbeTooHigh{false};    //!< the previous probe found the inflight too high
    bool m_prevProbePrecautionary{false}; //!< the previous probe was cut short
    bool m_isBwProbeStopping{false};   //!< the probe is ending
    bool m_checkProbeLoss{false};      //!< losses of this round count against the probe
    Ptr<UniformRandomVariable> m_rng;  //!< for the probe wait

    // acknowledgment aggregation
    uint64_t m_extraAcked[2]{0, 0};    //!< maximum extra data acknowledged, two windows
    uint32_t m_extraAckedWin{0};       //!< index of the current window
    uint64_t m_extraAckedRound{0};     //!< round of the current window
    Time m_ackEpochStart;              //!< start of the aggregation epoch
    uint64_t m_ackEpochAcked{0};       //!< bytes acknowledged in the epoch

    // ProbeRTT and the window
    Time m_probeRttDoneStamp;          //!< when ProbeRTT may end, zero until the pipe is drained
    bool m_probeRttRoundDone{false};   //!< a round passed in ProbeRTT
    uint64_t m_priorCwnd{0};           //!< window before ProbeRTT
    uint64_t m_probeRttCwnd{0};        //!< window of ProbeRTT
    uint32_t m_minPipeCwnd{0};         //!< BBR.MinPipeCwnd
    bool m_lastSampleAppLimited{false}; //!< the last sample was application limited
    uint64_t m_lastTxInFlight{0};      //!< data in flight of the last sample
};

} // namespace ns3

#endif // QUIC_BBR_V3_H
