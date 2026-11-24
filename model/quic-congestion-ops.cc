/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#define __STDC_LIMIT_MACROS

#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/nstime.h"
#include "quic-socket.h"
#include "quic-congestion-ops.h"
#include "quic-socket-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicCongestionControl");

NS_OBJECT_ENSURE_REGISTERED (QuicCongestionOps);

TypeId
QuicCongestionOps::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicCongestionControl")
    .SetParent<TcpNewReno> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicCongestionOps> ()
  ;
  return tid;
}

QuicCongestionOps::QuicCongestionOps (void)
  : TcpNewReno ()
{
  NS_LOG_FUNCTION (this);
}

QuicCongestionOps::QuicCongestionOps (
  const QuicCongestionOps& sock)
  : TcpNewReno (sock)
{
  NS_LOG_FUNCTION (this);
}

QuicCongestionOps::~QuicCongestionOps (void)
{}

bool
QuicCongestionOps::UsesPacingRate () const
{
  return false;
}

std::string
QuicCongestionOps::GetName () const
{
  return "QuicCongestionControl";
}

Ptr<TcpCongestionOps>
QuicCongestionOps::Fork ()
{
  return CopyObject<QuicCongestionOps> (this);
}

// Quic DRAFT 10

void
QuicCongestionOps::OnPacketSent (Ptr<TcpSocketState> tcb,
                                 SequenceNumber32 packetNumber,
                                 bool isAckOnly)
{
  NS_LOG_FUNCTION (this << packetNumber << isAckOnly);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  tcbd->m_timeOfLastSentPacket = Now ();
  tcbd->m_highTxMark = packetNumber;
}

void
QuicCongestionOps::OnAckReceived (Ptr<TcpSocketState> tcb,
                                  QuicSubheader &ack,
                                  std::vector<Ptr<QuicSocketTxItem> > newAcks,
                                  const struct RateSample *rs)
{
  NS_LOG_FUNCTION (this << rs);

  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  tcbd->m_largestAckedPacket = SequenceNumber32 (
    ack.GetLargestAcknowledged ());

  // newAcks are ordered from the highest packet number to the smalles
  Ptr<QuicSocketTxItem> lastAcked = newAcks.at (0);

  NS_LOG_LOGIC ("Updating RTT estimate");
  // If the largest acked is newly acked AND ack-eliciting, update the RTT.
  // RFC 9002 §3.1 #2,#5: RTT MUST only be sampled for ack-eliciting packets.
  if (lastAcked->m_packetNumber == tcbd->m_largestAckedPacket
      && lastAcked->m_ackEliciting)
    {
      tcbd->m_lastRtt = Now () - lastAcked->m_lastSent;
      UpdateRtt (tcbd, tcbd->m_lastRtt, MicroSeconds (ack.GetAckDelay ()));
    }

  NS_LOG_LOGIC ("Processing acknowledged packets");
  // Process each acked packet
  for (auto it = newAcks.rbegin (); it != newAcks.rend (); ++it)
    {
      // newAcks only holds newly acknowledged packets, including those acknowledged
      // after a gap (m_acked is only set once the packet leaves the sent list)
      OnPacketAcked (tcb, (*it));
    }
}

void
QuicCongestionOps::UpdateRtt (Ptr<TcpSocketState> tcb, Time latestRtt,
                              Time ackDelay)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  // RFC 9002 s5.2: min_rtt ignores the ack delay
  tcbd->m_minRtt = std::min (tcbd->m_minRtt, latestRtt);

  // RFC 9002 s5.3: the ack delay is ignored until the handshake is confirmed, is capped at the peer's
  // max_ack_delay and is not subtracted when the result would be below min_rtt
  Time adjustedRtt = latestRtt;
  if (tcbd->m_handshakeConfirmed)
    {
      ackDelay = std::min (ackDelay, tcbd->m_maxAckDelay);
      if (latestRtt >= tcbd->m_minRtt + ackDelay)
        {
          adjustedRtt = latestRtt - ackDelay;
        }
    }

  // latest_rtt is the raw sample: the time-threshold loss detection (RFC 9002 s6.1.2) uses it unadjusted
  tcbd->m_latestRtt = latestRtt;

  NS_LOG_LOGIC ("Update smoothed RTT");
  // Based on [RFC6298].
  if (tcbd->m_smoothedRtt == Seconds (0))
    {
      tcbd->m_smoothedRtt = latestRtt;
      tcbd->m_rttVar = latestRtt / 2;
    }
  else
    {
      Time rttVarSample = Time (
        std::abs ((tcbd->m_smoothedRtt - adjustedRtt).GetDouble ()));
      tcbd->m_rttVar = tcbd->m_rttVar * 3 / 4 + rttVarSample / 4;
      tcbd->m_smoothedRtt = tcbd->m_smoothedRtt * 7 / 8 + adjustedRtt / 8;
    }

}

void
QuicCongestionOps::OnPacketAcked (Ptr<TcpSocketState> tcb,
                                  Ptr<QuicSocketTxItem> ackedPacket)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  OnPacketAckedCC (tcbd, ackedPacket);

  // RFC 9002 §7.6.2: PTO does NOT reduce congestion window.
  // CWND reduction happens only via OnPacketsLost (confirmed loss via FACK or
  // time threshold). The old TCP-RTO recovery path (OnRetransmissionTimeoutVerified)
  // is not applicable to QUIC PTO semantics.
  tcbd->m_handshakeCount = 0;
  tcbd->m_tlpCount = 0;
  tcbd->m_rtoCount = 0;
}

bool
QuicCongestionOps::InRecovery (Ptr<TcpSocketState> tcb,
                               SequenceNumber32 packetNumber)
{
  NS_LOG_FUNCTION (this << packetNumber.GetValue ());
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  return packetNumber <= tcbd->m_endOfRecovery;
}

void
QuicCongestionOps::OnPacketAckedCC (Ptr<TcpSocketState> tcb,
                                    Ptr<QuicSocketTxItem> ackedPacket)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  NS_LOG_INFO ("Updating congestion window");
  if (InRecovery (tcb, ackedPacket->m_packetNumber))
    {
      NS_LOG_LOGIC ("In recovery");
      // Do not increase congestion window in recovery period.
      return;
    }
  // RFC 9002 §7.8: MUST NOT increase cwnd when application-limited (under-utilizing window)
  if (tcbd->m_appLimitedUntil > tcbd->m_delivered)
    {
      NS_LOG_LOGIC ("Application-limited: skip cwnd growth (RFC 9002 §7.8)");
      return;
    }
  if (tcbd->m_cWnd < tcbd->m_ssThresh)
    {
      NS_LOG_LOGIC ("In slow start");
      // Slow start.
      tcbd->m_cWnd += ackedPacket->m_packet->GetSize ();
    }
  else
    {
      NS_LOG_LOGIC ("In congestion avoidance");
      // Congestion Avoidance.
      if (tcbd->m_cWnd > (uint32_t) 0) {
          tcbd->m_cWnd += tcbd->m_segmentSize * ackedPacket->m_packet->GetSize ()
              / tcbd->m_cWnd;
      } else {
          tcbd->m_cWnd = tcbd->m_kMinimumWindow;
      }
    }
}

void
QuicCongestionOps::OnPacketsLost (
  Ptr<TcpSocketState> tcb, std::vector<Ptr<QuicSocketTxItem> > lostPackets)
{
  NS_LOG_LOGIC (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");

  if (lostPackets.empty ())
    {
      return;
    }
  auto largestLostPacket = *(lostPackets.end () - 1);

  NS_LOG_INFO ("Go in recovery mode");
  // Start a new recovery epoch if the lost packet is larger than the end of the previous recovery epoch.
  if (!InRecovery (tcbd, largestLostPacket->m_packetNumber))
    {
      tcbd->m_endOfRecovery = tcbd->m_highTxMark;
      OnCongestionEvent (tcbd);
    }

  // RFC 9002 §7.6.3: Persistent Congestion detection.
  // Conditions: (a) ≥2 lost packets, (b) valid RTT sample, (c) send-time span > duration.
  // Note: the "no intermediate ACK" refinement (§7.6.2) is not checked here because
  // OnPacketsLost() has no tx-buffer access; it is an edge-case that doesn't affect
  // the primary detection logic.
  if (tcbd->m_kPersistentCongestionByPto)
    {
      // msquic (QUIC_PERSISTENT_CONGESTION_THRESHOLD = 2): the loss is persistent congestion when it
      // follows more than 2 consecutive probe timeouts
      if (tcbd->m_ptoCountForLoss > 2)
        {
          NS_LOG_INFO ("Persistent congestion (msquic): loss after " << tcbd->m_ptoCountForLoss << " PTOs");
          OnPersistentCongestion (tcbd);
          tcbd->m_minRtt = tcbd->m_latestRtt;
        }
    }
  else if (lostPackets.size () >= 2 && tcbd->m_smoothedRtt > Seconds (0)
      && !tcbd->m_lostSpanHasAck)
    {
      Time kGranularity = MilliSeconds (1);
      Time ptoDuration = tcbd->m_smoothedRtt
                         + std::max (4 * tcbd->m_rttVar, kGranularity)
                         + tcbd->m_maxAckDelay;
      Time persistentCongestionDuration = ptoDuration * tcbd->m_kPersistentCongestionThreshold;

      Time oldestSendTime = lostPackets.front ()->m_lastSent;
      Time newestSendTime  = lostPackets.front ()->m_lastSent;
      for (auto &pkt : lostPackets)
        {
          if (pkt->m_lastSent < oldestSendTime)
            {
              oldestSendTime = pkt->m_lastSent;
            }
          if (pkt->m_lastSent > newestSendTime)
            {
              newestSendTime = pkt->m_lastSent;
            }
        }

      if (newestSendTime - oldestSendTime >= persistentCongestionDuration)
        {
          NS_LOG_INFO ("Persistent congestion detected — collapsing cwnd to minimum (RFC 9002 §7.6.3)");
          OnPersistentCongestion (tcbd);
          // RFC 9002 §5.2: reset min_rtt after persistent congestion
          tcbd->m_minRtt = tcbd->m_latestRtt;
        }
    }
}

void
QuicCongestionOps::OnSpuriousLoss (Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber)
{
  NS_LOG_FUNCTION (this << packetNumber);
}

void
QuicCongestionOps::OnPathChange (Ptr<TcpSocketState> tcb)
{
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  if (tcbd == nullptr)
    {
      return;
    }
  tcbd->m_cWnd = tcbd->m_initialCWnd;
  tcbd->m_ssThresh = tcbd->m_initialSsThresh;
  tcbd->m_endOfRecovery = tcbd->m_highTxMark;
}

void
QuicCongestionOps::OnCongestionEvent (Ptr<QuicSocketState> tcbd)
{
  tcbd->m_cWnd *= tcbd->m_kLossReductionFactor;
  if (tcbd->m_cWnd < tcbd->m_kMinimumWindow)
    {
      tcbd->m_cWnd = tcbd->m_kMinimumWindow;
    }
  tcbd->m_ssThresh = tcbd->m_cWnd;
}

void
QuicCongestionOps::OnPersistentCongestion (Ptr<QuicSocketState> tcbd)
{
  // RFC 9002 s7.6.2: only the window collapses; ssthresh keeps the value the congestion event gave it, so
  // slow start resumes from the minimum window up to it
  tcbd->m_cWnd = tcbd->m_kMinimumWindow;
}

void
QuicCongestionOps::OnRetransmissionTimeoutVerified (
  Ptr<TcpSocketState> tcb)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != nullptr, "tcb is not a QuicSocketState");
  NS_LOG_INFO ("Loss state");
  tcbd->m_cWnd = tcbd->m_kMinimumWindow;
  tcbd->m_congState = TcpSocketState::CA_LOSS;
}

} // namespace ns3
