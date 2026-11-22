/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * QUIC CUBIC congestion control, following the behaviour of msquic (cubic.c):
 * RFC 9438 (CUBIC) with the Reno-friendly region, fast convergence, HyStart++
 * (RFC 9406) and pacing.
 */
#ifndef QUIC_CUBIC_H
#define QUIC_CUBIC_H

#include "quic-congestion-ops.h"

namespace ns3 {

/**
 * \ingroup quic
 * \brief CUBIC congestion control for QUIC (default algorithm, as in msquic)
 */
class QuicCubic : public QuicCongestionOps
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  QuicCubic ();
  QuicCubic (const QuicCubic &other);
  ~QuicCubic () override;

  std::string GetName () const override;
  Ptr<TcpCongestionOps> Fork () override;

  void OnAckReceived (Ptr<TcpSocketState> tcb, QuicSubheader &ack,
                      std::vector<Ptr<QuicSocketTxItem> > newAcks,
                      const struct RateSample *rs) override;

  void OnSpuriousLoss (Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber) override;
  void OnPathChange (Ptr<TcpSocketState> tcb) override;

protected:
  void OnPacketAcked (Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket) override;
  void OnCongestionEvent (Ptr<QuicSocketState> tcbd) override;
  void OnPersistentCongestion (Ptr<QuicSocketState> tcbd) override;
  void OnRetransmissionTimeoutVerified (Ptr<TcpSocketState> tcb) override;

private:
  /**
   * \brief HyStart++ round and RTT tracking, run for each acknowledged packet
   * \param tcbd socket state
   * \param pn packet number acknowledged
   */
  void HyStartOnAck (Ptr<QuicSocketState> tcbd, SequenceNumber32 pn);

  /**
   * \brief Update the pacing rate from the window and the smoothed RTT
   * \param tcbd socket state
   */
  void UpdatePacing (Ptr<QuicSocketState> tcbd);

  /// HyStart++ phases
  enum HyStartState { HS_NOT_STARTED, HS_STARTED, HS_ACTIVE };

  double m_c;                    //!< CUBIC constant C (segments / s^3)
  double m_beta;                 //!< multiplicative decrease factor
  double m_windowMax;            //!< W_max in bytes
  double m_windowLastMax;        //!< previous W_max (fast convergence)
  double m_k;                    //!< time (s) for the cubic to reach W_max
  double m_aimdWindow;           //!< Reno-friendly window estimate in bytes
  Time m_congAvoidStart;         //!< start of the current congestion avoidance epoch
  bool m_epochStarted;           //!< m_congAvoidStart is valid
  bool m_hyStartEnabled;         //!< HyStart++ enabled
  HyStartState m_hyState;        //!< HyStart++ state
  SequenceNumber32 m_roundEnd;   //!< packet number ending the current HyStart++ round
  bool m_roundEndSet;            //!< m_roundEnd valid
  Time m_lastRoundMinRtt;        //!< minimum RTT of the previous round
  Time m_currRoundMinRtt;        //!< minimum RTT of the current round
  uint32_t m_rttSamples;         //!< RTT samples in the current round
  uint32_t m_cssRounds;          //!< rounds spent in conservative slow start
  Time m_cssBaselineMinRtt;      //!< baseline RTT when CSS was entered
  bool m_pacingEnabled;          //!< pace packets
  /// State saved before a congestion event, restored if the loss was spurious
  struct SavedState
  {
    bool valid {false};
    uint32_t cwnd {0};
    uint32_t ssThresh {0};
    double windowMax {0};
    double windowLastMax {0};
    double aimdWindow {0};
    uint32_t bytesInFlightMax {0};
    bool epochStarted {false};
    Time congAvoidStart;
    double k {0};
    SequenceNumber32 endOfRecovery;
  } m_saved;
  uint32_t m_bytesInFlightMax;   //!< maximum bytes in flight (window utilisation check)
};

} // namespace ns3

#endif /* QUIC_CUBIC_H */
