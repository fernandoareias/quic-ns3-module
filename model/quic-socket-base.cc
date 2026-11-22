/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          Umberto Paro <umberto.paro@me.com>
 *
 */
/*
 #define NS_LOG_APPEND_CONTEXT \
  if (m_node and m_connectionId) { std::clog << " [node " << m_node->GetId () << " socket " << m_connectionId << "] "; }
*/

#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/random-variable-stream.h"
#include "ns3/nstime.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/trace-source-accessor.h"
#include "quic-socket-base.h"
#include "quic-congestion-ops.h"
#include "ns3/tcp-congestion-ops.h"
#include "quic-header.h"
#include "quic-l4-protocol.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv6-end-point.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/tcp-header.h"
#include "ns3/tcp-option-winscale.h"
#include "ns3/tcp-option-ts.h"
#include "ns3/tcp-option-sack-permitted.h"
#include "ns3/tcp-option-sack.h"
#include "ns3/rtt-estimator.h"
#include "quic-socket-tx-edf-scheduler.h"
#include <math.h>
#include <algorithm>
#include <vector>
#include <sstream>
#include <ns3/core-module.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketBase");

NS_OBJECT_ENSURE_REGISTERED (QuicSocketBase);
NS_OBJECT_ENSURE_REGISTERED (QuicSocketState);

const uint16_t QuicSocketBase::MIN_INITIAL_PACKET_SIZE = 1200;

// RFC 9002 §2: Map QuicHeader type to PacketNumberSpace.
PacketNumberSpace
QuicSocketBase::GetPacketNumberSpace (const QuicHeader &header)
{
  if (header.IsInitial ())   return INITIAL_SPACE;
  if (header.IsHandshake ()) return HANDSHAKE_SPACE;
  return APP_DATA_SPACE;     // short header (1-RTT) or 0-RTT
}

// RFC 9002 §9.1 / RFC 9001 §4.9: Discard Initial packet number space.
void
QuicSocketBase::DiscardInitialPacketSpace ()
{
  if (m_initialSpaceDiscarded)
    {
      return;
    }
  NS_LOG_INFO ("Discarding Initial packet number space (RFC 9002 §9.1)");
  m_tcb->m_lossTimeSpace[INITIAL_SPACE]           = Seconds (0);
  m_tcb->m_largestAckedPacketSpace[INITIAL_SPACE] = SequenceNumber32 (0);
  m_initialSpaceDiscarded = true;
}

// RFC 9002 §9.1 / RFC 9001 §4.9: Discard Handshake packet number space.
void
QuicSocketBase::DiscardHandshakePacketSpace ()
{
  if (m_handshakeSpaceDiscarded)
    {
      return;
    }
  NS_LOG_INFO ("Discarding Handshake packet number space (RFC 9002 §9.1)");
  m_tcb->m_lossTimeSpace[HANDSHAKE_SPACE]           = Seconds (0);
  m_tcb->m_largestAckedPacketSpace[HANDSHAKE_SPACE] = SequenceNumber32 (0);
  m_handshakeSpaceDiscarded = true;
}

TypeId
QuicSocketBase::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketBase")
    .SetParent<QuicSocket> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketBase> ()
    .AddAttribute ("InitialVersion",
                   "QUIC version used by the client; a reserved version (0x?a?a?a?a, RFC 9000 s15) forces a version negotiation round trip",
                   UintegerValue (QUIC_VERSION),
                   MakeUintegerAccessor (&QuicSocketBase::m_vers),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("IdleTimeout",
                   "Idle timeout value after which the socket is closed (0 disables it; the peer's max_idle_timeout can only shorten it)",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&QuicSocketBase::m_idleTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("DisconnectTimeout",
                   "Close the connection after this long without ACK progress while probing (msquic: 16 s)",
                   TimeValue (Seconds (16)),
                   MakeTimeAccessor (&QuicSocketBase::m_disconnectTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MaxStreamData",
                   "Stream Maximum Data",
                   UintegerValue (65536),           // msquic StreamRecvWindowDefault
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_data),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxData",
                   "Connection Maximum Data",
                   UintegerValue (16777216),        // msquic ConnFlowControlWindow (16 MiB)
                   MakeUintegerAccessor (&QuicSocketBase::m_max_data),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxStreamIdBidi",
                   "Number of bidirectional streams the peer may open (initial_max_streams_bidi)",
                   UintegerValue (0),                   // msquic PeerBidiStreamCount: no peer streams until the application allows them
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_id_bidi),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxStreamIdUni", "Number of unidirectional streams the peer may open (initial_max_streams_uni)",
                   UintegerValue (0),                                  // msquic PeerUnidiStreamCount
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_id_uni),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxTrackedGaps", "Maximum number of gaps in an ACK",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QuicSocketBase::m_maxTrackedGaps),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("AckToleranceCwndDivisor",
                   "The ACK tolerance asked of the peer (ACK_FREQUENCY) is at most the congestion window in packets "
                   "divided by this, so that the peer acknowledges several times per round trip; 0 keeps msquic's "
                   "batch size + 1 whatever the window",
                   UintegerValue (8),
                   MakeUintegerAccessor (&QuicSocketBase::m_ackToleranceCwndDivisor),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("OmitConnectionId", "Omit ConnectionId field in Short QuicHeader format",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketBase::m_omit_connection_id),
                   MakeBooleanChecker ())
    .AddAttribute ("MaxPacketSize", "Maximum Packet Size",
                   UintegerValue (1460),
                   MakeUintegerAccessor (&QuicSocketBase::GetSegSize,
                                         &QuicSocketBase::SetSegSize),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("SocketSndBufSize", "QuicSocketBase maximum transmit buffer size (bytes)",
                   UintegerValue (4194304),                                  // 4 MiB
                   MakeUintegerAccessor (&QuicSocketBase::GetSocketSndBufSize,
                                         &QuicSocketBase::SetSocketSndBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SocketRcvBufSize", "QuicSocketBase receive buffer size (bytes); acknowledged data is never dropped, so a burst can exceed it",
                   UintegerValue (4194304),                                  // 4 MiB
                   MakeUintegerAccessor (&QuicSocketBase::GetSocketRcvBufSize,
                                         &QuicSocketBase::SetSocketRcvBufSize),
                   MakeUintegerChecker<uint32_t> ())
    //	.AddAttribute ("StatelessResetToken, "Stateless Reset Token",
    //				   UintegerValue (0),
    //				   MakeUintegerAccessor (&QuicSocketBase::m_stateless_reset_token),
    //				   MakeUintegerChecker<uint128_t> ())
    .AddAttribute ("AckDelayExponent", "Ack Delay Exponent", 
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketBase::m_ack_delay_exponent),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("DisableActiveMigration", "Announce disable_active_migration (RFC 9000 s18.2): the peer must not "
                   "migrate the connection to another address on purpose",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketBase::m_disableActiveMigration),
                   MakeBooleanChecker ())
    .AddAttribute ("FlushOnClose", "Determines the connection close behavior",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketBase::m_flushOnClose),
                   MakeBooleanChecker ())
    .AddAttribute ("kMaxTLPs",
                   "Maximum number of tail loss probes before an RTO fires",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxTLPs),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kMaxPtoCount",
                   "RFC 9002 §6.2.1: max consecutive PTOs without new ACK before abandoning connection",
                   UintegerValue (8),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxPtoCount),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kReorderingThreshold", "Packet reordering threshold (RFC 9002 kPacketThreshold): a packet is lost once it is this many packet numbers "
                   "below an acknowledged one; msquic's rule is the same with 4",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kReorderingThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kTimeReorderingFraction", "Maximum reordering in time space before time based loss detection considers a packet lost",
                   DoubleValue (9.0 / 8.0),
                   MakeDoubleAccessor (&QuicSocketState::m_kTimeReorderingFraction),
                   MakeDoubleChecker<double> (0))
    .AddAttribute ("kUsingTimeLossDetection", "Whether time based loss detection is in use", 
                   BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketState::m_kUsingTimeLossDetection),
                   MakeBooleanChecker ())
    .AddAttribute ("kMinTLPTimeout", "Minimum time in the future a tail loss probe alarm may be set for",
                   TimeValue (MilliSeconds (10)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinTLPTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kMinRTOTimeout", "Minimum time in the future an RTO alarm may be set for",
                   TimeValue (MilliSeconds (200)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinRTOTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kDelayedAckTimeout", "The length of the peer's delayed ACK timer",
                   TimeValue (MilliSeconds (25)),
                   MakeTimeAccessor (&QuicSocketState::m_kDelayedAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kDefaultInitialRtt", "The default RTT used before an RTT sample is taken",
                   TimeValue (MilliSeconds (333)),
                   MakeTimeAccessor (&QuicSocketState::m_kDefaultInitialRtt),
                   MakeTimeChecker ())
    .AddAttribute ("InitialSlowStartThreshold",
                   "QUIC initial slow start threshold (bytes)",
                   UintegerValue (INT32_MAX),
                   MakeUintegerAccessor (&QuicSocketBase::GetInitialSSThresh,
                                         &QuicSocketBase::SetInitialSSThresh),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("InitialPacketSize",
                   "QUIC initial slow start threshold (bytes)",
                   UintegerValue (1200),
                   MakeUintegerAccessor (&QuicSocketBase::GetInitialPacketSize,
                                         &QuicSocketBase::SetInitialPacketSize),
                   MakeUintegerChecker<uint32_t> (
                     QuicSocketBase::MIN_INITIAL_PACKET_SIZE, UINT32_MAX))
    .AddAttribute ("DestCidUpdateIdleTimeout",
                   "After this much time without sending, the next flush switches to a new destination "
                   "connection id (msquic DestCidUpdateIdleTimeoutMs)",
                   TimeValue (Seconds (20)),
                   MakeTimeAccessor (&QuicSocketBase::m_destCidUpdateIdleTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("EnableMtuDiscovery",
                   "Probe the path MTU (DPLPMTUD) like msquic: start at a 1288 byte MTU and grow towards the segment size",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketBase::m_pmtudEnabled),
                   MakeBooleanChecker ())
    .AddAttribute ("SchedulingPolicy",
                   "Scheduling policy among streams",
                   TypeIdValue (QuicSocketTxStreamFifoScheduler::GetTypeId ()),
                   MakeTypeIdAccessor (&QuicSocketBase::m_schedulingTypeId),
                   MakeTypeIdChecker ())
    .AddAttribute ("DefaultLatency",
                   "Default latency bound for the EDF scheduler",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&QuicSocketBase::m_defaultLatency),
                   MakeTimeChecker ())
    .AddAttribute ("LegacyCongestionControl", "When true, use TCP implementations for the congestion control",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketBase::m_quicCongestionControlLegacy),
                   MakeBooleanChecker ())
    .AddAttribute ("TCB",
                   "The connection's QuicSocketState",
                   PointerValue (),
                   MakePointerAccessor (&QuicSocketBase::m_tcb),
                   MakePointerChecker<QuicSocketState> ())
    // .AddTraceSource ("RTO", "Retransmission timeout",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_rto),
    //                  "ns3::Time::TracedValueCallback").AddTraceSource (
    //     "IdleTO", "Idle timeout",
    //     MakeTraceSourceAccessor (&QuicSocketBase::m_idleTimeout),
    //     "ns3::Time::TracedValueCallback").AddTraceSource (
    //     "DrainingPeriodTO", "Draining Period timeout",
    //     MakeTraceSourceAccessor (&QuicSocketBase::m_drainingPeriodTimeout),
    //     "ns3::Time::TracedValueCallback");
    .AddTraceSource ("SpuriousLoss",
                     "A packet declared lost was acknowledged later (packet number)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_spuriousLossTrace),
                     "ns3::TracedCallback::Uint32Callback")
    .AddTraceSource ("RTO",
                     "Retransmission timeout",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_rto),
                     "ns3::Time::TracedValueCallback")
    .AddTraceSource ("RTT",
                     "Last RTT sample",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_lastRtt),
                     "ns3::Time::TracedValueCallback")
    .AddTraceSource ("NextTxSequence",
                     "Next sequence number to send (SND.NXT)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_nextTxSequenceTrace),
                     "ns3::SequenceNumber32TracedValueCallback")
    .AddTraceSource ("HighestSequence",
                     "Highest sequence number ever sent in socket's life time",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_highTxMarkTrace),
                     "ns3::SequenceNumber32TracedValueCallback")
    // .AddTraceSource ("State",
    //                  "TCP state",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_state),
    //                  "ns3::TcpStatesTracedValueCallback")
    .AddTraceSource ("CongState",
                     "TCP Congestion machine state",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_congStateTrace),
                     "ns3::TcpSocketState::TcpCongStatesTracedValueCallback")
    // .AddTraceSource ("AdvWND",
    //                  "Advertised Window Size",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_advWnd),
    //                  "ns3::TracedValueCallback::Uint32")
    // .AddTraceSource ("RWND",
    //                  "Remote side's flow control window",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_rWnd),
    //                  "ns3::TracedValueCallback::Uint32")
    // .AddTraceSource ("BytesInFlight",
    //                  "Socket estimation of bytes in flight",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_bytesInFlight),
    //                  "ns3::TracedValueCallback::Uint32")
    // .AddTraceSource ("HighestRxSequence",
    //                  "Highest sequence number received from peer",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_highRxMark),
    //                  "ns3::SequenceNumber32TracedValueCallback")
    // .AddTraceSource ("HighestRxAck",
    //                  "Highest ack received from peer",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_highRxAckMark),
    //                  "ns3::SequenceNumber32TracedValueCallback")
    .AddTraceSource ("CongestionWindow",
                     "The QUIC connection's congestion window",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_cWndTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("SlowStartThreshold",
                     "TCP slow start threshold (bytes)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_ssThTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("Tx",
                     "Send QUIC packet to UDP protocol",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_txTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
    .AddTraceSource ("Rx",
                     "Receive QUIC packet from UDP protocol",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_rxTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
  ;
  return tid;
}

TypeId
QuicSocketState::GetTypeId (void)
{
  static TypeId tid =
    TypeId ("ns3::QuicSocketState")
    .SetParent<TcpSocketState> ()
    .SetGroupName ("Internet")
    .AddAttribute ("kMaxTLPs",
                   "Maximum number of tail loss probes before an RTO fires",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxTLPs),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kMaxPtoCount",
                   "RFC 9002 §6.2.1: max consecutive PTOs without new ACK before abandoning connection",
                   UintegerValue (8),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxPtoCount),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kReorderingThreshold",
                   "Maximum reordering in packet number space before FACK style loss detection considers a packet lost",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kReorderingThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kTimeReorderingFraction",
                   "Maximum reordering in time space before time based loss detection considers a packet lost",
                   DoubleValue (9.0 / 8.0),
                   MakeDoubleAccessor (&QuicSocketState::m_kTimeReorderingFraction),
                   MakeDoubleChecker<double> (0))
    .AddAttribute ("kUsingTimeLossDetection",
                   "Whether time based loss detection is in use", BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketState::m_kUsingTimeLossDetection),
                   MakeBooleanChecker ())
    .AddAttribute ("kMinTLPTimeout",
                   "Minimum time in the future a tail loss probe alarm may be set for",
                   TimeValue (MilliSeconds (10)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinTLPTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kMinRTOTimeout",
                   "Minimum time in the future an RTO alarm may be set for",
                   TimeValue (MilliSeconds (200)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinRTOTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kDelayedAckTimeout", "The lenght of the peer's delayed ack timer",
                   TimeValue (MilliSeconds (25)),
                   MakeTimeAccessor (&QuicSocketState::m_kDelayedAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kDefaultInitialRtt",
                   "The default RTT used before an RTT sample is taken",
                   TimeValue (MilliSeconds (333)),
                   MakeTimeAccessor (&QuicSocketState::m_kDefaultInitialRtt),
                   MakeTimeChecker ())
    .AddAttribute ("kMaxPacketsReceivedBeforeAckSend",
                   "The maximum number of packets without sending an ACK",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxPacketsReceivedBeforeAckSend),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kPersistentCongestionThreshold",
                   "RFC 9002 §7.6.3: multiplier for the persistent congestion duration. RECOMMENDED = 3",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kPersistentCongestionThreshold),
                   MakeUintegerChecker<uint32_t> (1, UINT32_MAX))
    .AddAttribute ("PersistentCongestionByPto",
                   "msquic style: persistent congestion is declared when a loss is detected after more than 2 "
                   "consecutive PTOs; false selects the RFC 9002 s7.6.3 duration test",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketState::m_kPersistentCongestionByPto),
                   MakeBooleanChecker ())
  ;
  return tid;
}

QuicSocketState::QuicSocketState ()
  : TcpSocketState (),
    m_lossDetectionAlarm (),
    m_handshakeCount (0),
    m_tlpCount (
      0),
    m_rtoCount (0),
    m_largestSentBeforeRto (0),
    m_timeOfLastSentPacket (
      Seconds (0)),
    m_largestAckedPacket (0),
    m_smoothedRtt (Seconds (0)),
    m_rttVar (0),
    m_minRtt (Time::Max ()),               // RFC 9002 s5.2: no minimum until the first RTT sample
    m_maxAckDelay (MilliSeconds (25)),     // RFC 9000 s18.2: default until the peer announces its own
    m_timeOfLastAckElicitingSent (Seconds (0)),
    m_lossTime (Seconds (0)),
    m_kMinimumWindow (
      2 * m_segmentSize),
    m_kLossReductionFactor (0.5),
    m_kPersistentCongestionThreshold (3),
    m_endOfRecovery (0),
    m_kMaxTLPs (
      2),
    m_kMaxPtoCount (8),
    m_kReorderingThreshold (3),
    m_kTimeReorderingFraction (9.0 / 8.0),
    m_kUsingTimeLossDetection (true),  // RFC 9002 §6.1.2
    m_kMinTLPTimeout (MilliSeconds (10)),
    m_kMinRTOTimeout (
      MilliSeconds (200)),
    m_kDelayedAckTimeout (MilliSeconds (25)),
    m_alarmType (0),
    m_nextAlarmTrigger (Seconds (100)),
    m_kDefaultInitialRtt (
      MilliSeconds (333)),
    m_kMaxPacketsReceivedBeforeAckSend (20)
{
  m_lossDetectionAlarm.Cancel ();
  // RFC 9002 §2: initialize per-space tracking arrays
  for (int s = 0; s < NUM_SPACES; ++s)
    {
      m_largestAckedPacketSpace[s] = SequenceNumber32 (0);
      m_lossTimeSpace[s]           = Seconds (0);
    }
}

QuicSocketState::QuicSocketState (const QuicSocketState &other)
  : TcpSocketState (other),
    m_lossDetectionAlarm (other.m_lossDetectionAlarm),
    m_handshakeCount (
      other.m_handshakeCount),
    m_tlpCount (other.m_tlpCount),
    m_rtoCount (
      other.m_rtoCount),
    m_largestSentBeforeRto (
      other.m_largestSentBeforeRto),
    m_timeOfLastSentPacket (
      other.m_timeOfLastSentPacket),
    m_largestAckedPacket (
      other.m_largestAckedPacket),
    m_smoothedRtt (
      other.m_smoothedRtt),
    m_rttVar (other.m_rttVar),
    m_minRtt (
      other.m_minRtt),
    m_maxAckDelay (other.m_maxAckDelay),
    m_timeOfLastAckElicitingSent (other.m_timeOfLastAckElicitingSent),
    m_lossTime (
      other.m_lossTime),
    m_kMinimumWindow (other.m_kMinimumWindow),
    m_kLossReductionFactor (
      other.m_kLossReductionFactor),
    m_kPersistentCongestionThreshold (other.m_kPersistentCongestionThreshold),
    m_kPersistentCongestionByPto (other.m_kPersistentCongestionByPto),
    m_ptoCountForLoss (other.m_ptoCountForLoss),
    m_endOfRecovery (
      other.m_endOfRecovery),
    m_kMaxTLPs (other.m_kMaxTLPs),
    m_kMaxPtoCount (other.m_kMaxPtoCount),
    m_kReorderingThreshold (
      other.m_kReorderingThreshold),
    m_kTimeReorderingFraction (
      other.m_kTimeReorderingFraction),
    m_kUsingTimeLossDetection (
      other.m_kUsingTimeLossDetection),
    m_kMinTLPTimeout (
      other.m_kMinTLPTimeout),
    m_kMinRTOTimeout (other.m_kMinRTOTimeout),
    m_kDelayedAckTimeout (
      other.m_kDelayedAckTimeout),
    m_kDefaultInitialRtt (
      other.m_kDefaultInitialRtt),
    m_kMaxPacketsReceivedBeforeAckSend (other.m_kMaxPacketsReceivedBeforeAckSend)
{
  m_lossDetectionAlarm.Cancel ();
  for (int s = 0; s < NUM_SPACES; ++s)
    {
      m_largestAckedPacketSpace[s] = other.m_largestAckedPacketSpace[s];
      m_lossTimeSpace[s]           = other.m_lossTimeSpace[s];
    }
}

QuicSocketBase::QuicSocketBase (void)
  : QuicSocket (),
    m_endPoint (0),
    m_endPoint6 (0),
    m_node (0),
    m_quicl4 (0),
    m_quicl5 (0),
    m_socketState (
      IDLE),
    m_transportErrorCode (
      QuicSubheader::TransportErrorCodes_t::NO_ERROR),
    m_serverBusy (false),
    m_errno (
      ERROR_NOTERROR),
    m_connected (false),
    m_connectionId (0),
    m_vers (
      QUIC_VERSION_NS3_IMPL),
    m_keyPhase (QuicHeader::PHASE_ZERO),
    m_spinBit (false),
    m_lastReceived (Seconds (0.0)),
    m_largestRecvTime (Seconds (0.0)),
    m_bytesReceivedPreValidation (0),
    m_bytesSentPreValidation (0),
    m_peerAddressValidated (false),
    m_initial_max_stream_data (0),
    m_initial_max_stream_data_bidi_remote (0),
    m_initial_max_stream_data_uni (0),
    m_max_data (0),
    m_initial_max_stream_id_bidi (0),
    m_idleTimeout (
      Seconds (300.0)),
    m_omit_connection_id (false),
    m_ack_delay_exponent (3),
    m_initial_max_stream_id_uni (0),
    m_maxTrackedGaps (20),
    m_ackToleranceCwndDivisor (8),
    m_receivedTransportParameters (
      false),
    m_couldContainTransportParameters (true),
    m_rto (
      Seconds (30.0)),
    m_drainingPeriodTimeout (Seconds (90.0)),
    m_flushOnClose (true),
    m_closeOnEmpty (false),
    m_congestionControl (
      0),
    m_lastRtt (Seconds (0.0)),
    m_queue_ack (false),
    m_numPacketsReceivedSinceLastAckSent (0),
    m_pacingTimer (Timer::REMOVE_ON_DESTROY)
{
  NS_LOG_FUNCTION (this);


  m_rxBuffer = CreateObject<QuicSocketRxBuffer> ();
  m_txBuffer = CreateObject<QuicSocketTxBuffer> ();
  m_receivedPacketNumbers = QuicPnRanges ();

  m_tcb = CreateObject<QuicSocketState> ();
  m_tcb->m_cWnd = m_tcb->m_initialCWnd;
  m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
  m_quicCongestionControlLegacy = false;
  m_txBuffer->SetQuicSocketState (m_tcb);

  m_tcb->m_pacingRate = m_tcb->m_maxPacingRate;
  m_pacingTimer.SetFunction (&QuicSocketBase::NotifyPacingPerformed, this);

  /**
   * [IETF DRAFT 10 - Quic Transport: sec 5.7.1]
   *
   * The initial number for a packet number MUST be selected randomly from a range between
   * 0 and 2^32 -1025 (inclusive).
   * However, in this implementation, we set the sequence number to 0
   *
   */
  if (!m_quicCongestionControlLegacy)
    {
      Ptr<UniformRandomVariable> rand =
        CreateObject<UniformRandomVariable> ();
      m_tcb->m_nextTxSequence = SequenceNumber32 (0);
      // (uint32_t) rand->GetValue (0, pow (2, 32) - 1025));
    }

  // connect callbacks
  bool ok;
  ok = m_tcb->TraceConnectWithoutContext ("CongestionWindow",
                                          MakeCallback (&QuicSocketBase::UpdateCwnd, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to CWND trace");

  ok = m_tcb->TraceConnectWithoutContext ("SlowStartThreshold",
                                          MakeCallback (&QuicSocketBase::UpdateSsThresh, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to SSTHR trace");

  ok = m_tcb->TraceConnectWithoutContext ("CongState",
                                          MakeCallback (&QuicSocketBase::UpdateCongState, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to CongState trace");

  ok = m_tcb->TraceConnectWithoutContext ("NextTxSequence",
                                          MakeCallback (&QuicSocketBase::UpdateNextTxSequence, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to TxSequence trace");

  ok = m_tcb->TraceConnectWithoutContext ("HighestSequence",
                                          MakeCallback (&QuicSocketBase::UpdateHighTxMark, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to highest sequence trace");

}

QuicSocketBase::QuicSocketBase (const QuicSocketBase& sock)   // Copy constructor
  : QuicSocket (sock),
    m_endPoint (0),
    m_endPoint6 (0),
    m_node (sock.m_node),
    m_quicl4 (sock.m_quicl4),
    m_quicl5 (0),
    m_socketState (LISTENING),
    m_transportErrorCode (sock.m_transportErrorCode),
    m_serverBusy (sock.m_serverBusy),
    m_errno (sock.m_errno),
    m_connected (sock.m_connected),
    m_connectionId (0),
    m_vers (sock.m_vers),
    m_keyPhase (QuicHeader::PHASE_ZERO),
    m_spinBit (sock.m_spinBit),
    m_lastReceived (sock.m_lastReceived),
    m_largestRecvTime (sock.m_largestRecvTime),
    m_bytesReceivedPreValidation (0),
    m_bytesSentPreValidation (0),
    m_peerAddressValidated (false),
    m_initial_max_stream_data (sock.m_initial_max_stream_data),
    m_initial_max_stream_data_bidi_remote (sock.m_initial_max_stream_data_bidi_remote),
    m_initial_max_stream_data_uni (sock.m_initial_max_stream_data_uni),
    m_max_data (sock.m_max_data),
    m_initial_max_stream_id_bidi (sock.m_initial_max_stream_id_bidi),
    m_idleTimeout (sock.m_idleTimeout),
    m_omit_connection_id (sock.m_omit_connection_id),
    m_ack_delay_exponent (sock.m_ack_delay_exponent),
    m_disableActiveMigration (sock.m_disableActiveMigration),
    m_initial_max_stream_id_uni (sock.m_initial_max_stream_id_uni),
    m_maxTrackedGaps (sock.m_maxTrackedGaps),
    m_ackToleranceCwndDivisor (sock.m_ackToleranceCwndDivisor),
    m_receivedTransportParameters (sock.m_receivedTransportParameters),
    m_couldContainTransportParameters (sock.m_couldContainTransportParameters),
    m_rto (sock.m_rto),
    m_drainingPeriodTimeout (sock.m_drainingPeriodTimeout),
    m_flushOnClose (sock.m_flushOnClose),
    m_closeOnEmpty (sock.m_closeOnEmpty),
    m_lastRtt (sock.m_lastRtt),
    m_quicCongestionControlLegacy (sock.m_quicCongestionControlLegacy),
    m_queue_ack (sock.m_queue_ack),
    m_numPacketsReceivedSinceLastAckSent (sock.m_numPacketsReceivedSinceLastAckSent),
    m_lastMaxData(0),
    m_maxDataInterval(10),
    m_initialPacketSize (sock.m_initialPacketSize),
    m_pacingTimer (Timer::REMOVE_ON_DESTROY),
    m_txTrace (sock.m_txTrace),
    m_rxTrace (sock.m_rxTrace)
{
  NS_LOG_FUNCTION (this);

//  Callback<void, Ptr< Socket > > vPS = MakeNullCallback<void, Ptr<Socket> > ();
//  Callback<void, Ptr<Socket>, const Address &> vPSA = MakeNullCallback<void, Ptr<Socket>, const Address &> ();
//  Callback<void, Ptr<Socket>, uint32_t> vPSUI = MakeNullCallback<void, Ptr<Socket>, uint32_t> ();
//  SetConnectCallback (vPS, vPS);
//  SetDataSentCallback (vPSUI);
//  SetSendCallback (vPSUI);
//  SetRecvCallback (vPS);
  m_txBuffer = CopyObject (sock.m_txBuffer);
  // CopyObject copies the buffer's pointer to the scheduler: a clone needs a scheduler of its own,
  // or the connections accepted by one listener would serve each other's queued frames
  m_schedulingTypeId = sock.m_schedulingTypeId;
  m_defaultLatency = sock.m_defaultLatency;
  m_streamPriorities = sock.m_streamPriorities;
  InitializeScheduling ();
  m_rxBuffer = CopyObject (sock.m_rxBuffer);
  m_receivedPacketNumbers = QuicPnRanges ();

  m_tcb = CopyObject (sock.m_tcb);
  if (sock.m_congestionControl)
    {
      m_congestionControl = sock.m_congestionControl->Fork ();
    }
  m_quicCongestionControlLegacy = sock.m_quicCongestionControlLegacy;
  m_txBuffer->SetQuicSocketState (m_tcb);

  m_tcb->m_pacingRate = m_tcb->m_maxPacingRate;
  m_pacingTimer.SetFunction (&QuicSocketBase::NotifyPacingPerformed, this);

  /**
   * [IETF DRAFT 10 - Quic Transport: sec 5.7.1]
   *
   * The initial value for a packet number MUST be selected randomly from a range between
   * 0 and 2^32 -1025 (inclusive).
   *
   */
  if (!m_quicCongestionControlLegacy)
    {
      Ptr<UniformRandomVariable> rand =
        CreateObject<UniformRandomVariable> ();
      m_tcb->m_nextTxSequence = SequenceNumber32 (0);
      // (uint32_t) rand->GetValue (0, pow (2, 32) - 1025));
    }
}

QuicSocketBase::~QuicSocketBase (void)
{
  NS_LOG_FUNCTION (this);

  m_node = 0;
  if (m_endPoint != nullptr)
    {
      NS_ASSERT (m_quicl4 != nullptr);
      NS_ASSERT (m_endPoint != nullptr);
      m_quicl4->DeAllocate (m_endPoint);
      NS_ASSERT (m_endPoint == nullptr);
    }
  if (m_endPoint6 != nullptr)
    {
      NS_ASSERT (m_quicl4 != nullptr);
      NS_ASSERT (m_endPoint6 != nullptr);
      m_quicl4->DeAllocate (m_endPoint6);
      NS_ASSERT (m_endPoint6 == nullptr);
    }
  m_quicl4 = 0;
  //CancelAllTimers ();
  m_pacingTimer.Cancel ();
}

/* Inherit from Socket class: Bind socket to an end-point in QuicL4Protocol */
int
QuicSocketBase::Bind (void)
{
  //NS_LOG_FUNCTION (this);
  m_endPoint = m_quicl4->Allocate ();
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }

  m_quicl4->UdpBind (this);
  return SetupCallback ();
}

int
QuicSocketBase::Bind (const Address &address)
{
  NS_LOG_FUNCTION (this);
  if (InetSocketAddress::IsMatchingType (address))
    {
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      Ipv4Address ipv4 = transport.GetIpv4 ();
      uint16_t port = transport.GetPort ();
      //SetIpTos (transport.GetTos ());
      if (ipv4 == Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_quicl4->Allocate ();
        }
      else if (ipv4 == Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_quicl4->Allocate (GetBoundNetDevice (), port);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_quicl4->Allocate (ipv4);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_quicl4->Allocate (GetBoundNetDevice (), ipv4, port);
        }
      if (0 == m_endPoint)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address ipv6 = transport.GetIpv6 ();
      uint16_t port = transport.GetPort ();
      if (ipv6 == Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 ();
        }
      else if (ipv6 == Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (GetBoundNetDevice (), port);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (ipv6);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (GetBoundNetDevice (), ipv6, port);
        }
      if (0 == m_endPoint6)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }

  m_quicl4->UdpBind (address, this);
  return SetupCallback ();
}

int
QuicSocketBase::Bind6 (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint6 = m_quicl4->Allocate6 ();
  if (0 == m_endPoint6)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }

  m_quicl4->UdpBind6 (this);
  return SetupCallback ();
}

/* Inherit from Socket class: Bind this socket to the specified NetDevice */
void
QuicSocketBase::BindToNetDevice (Ptr<NetDevice> netdevice)
{
  NS_LOG_FUNCTION (this);

  m_quicl4->BindToNetDevice (this, netdevice);
}

int
QuicSocketBase::Listen (void)
{
  NS_LOG_FUNCTION (this);
  if (m_socketType == NONE)
    {
      m_socketType = SERVER;
    }

  if (m_socketState != IDLE and m_socketState != QuicSocket::CONNECTING_SVR)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  bool res = m_quicl4->SetListener (this);
  NS_ASSERT (res);

  SetState (LISTENING);

  return 0;
}

int
QuicSocketBase::Connect (const Address & address)
{
  NS_LOG_FUNCTION (this);

  if (InetSocketAddress::IsMatchingType (address))
    {
      if (m_endPoint == nullptr)
        {
          if (Bind () == -1)
            {
              NS_ASSERT (m_endPoint == nullptr);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint != nullptr);
        }
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      m_endPoint->SetPeer (transport.GetIpv4 (), transport.GetPort ());
      //SetIpTos (transport.GetTos ());
      m_endPoint6 = nullptr;

      // Get the appropriate local address and port number from the routing protocol and set up endpoint
      /*if (SetupEndpoint () != 0)
        {
          NS_LOG_ERROR ("Route to destination does not exist ?!");
          return -1;
        }*/
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      // If we are operating on a v4-mapped address, translate the address to
      // a v4 address and re-call this function
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address v6Addr = transport.GetIpv6 ();
      if (v6Addr.IsIpv4MappedAddress () == true)
        {
          Ipv4Address v4Addr = v6Addr.GetIpv4MappedAddress ();
          return Connect (InetSocketAddress (v4Addr, transport.GetPort ()));
        }

      if (m_endPoint6 == nullptr)
        {
          if (Bind6 () == -1)
            {
              NS_ASSERT (m_endPoint6 == nullptr);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint6 != nullptr);
        }
      m_endPoint6->SetPeer (v6Addr, transport.GetPort ());
      m_endPoint = nullptr;

      // Get the appropriate local address and port number from the routing protocol and set up endpoint
      /*if (SetupEndpoint6 () != 0)
        {
          NS_LOG_ERROR ("Route to destination does not exist ?!");
          return -1;
        }*/
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }


  if (m_socketType == NONE)
    {
      m_socketType = CLIENT;
    }

  if (m_quicl5 == nullptr)
    {
      m_quicl5 = CreateStreamController ();
      m_quicl5->CreateHandshakeStream ();
    }

  // check if the address is in a list of known and authenticated addresses
  auto result = std::find (
    m_quicl4->GetAuthAddresses ().begin (), m_quicl4->GetAuthAddresses ().end (),
    InetSocketAddress::ConvertFrom (address).GetIpv4 ());

  // Without 0-RTT enabled a known server still gets a full handshake: msquic has no session resumption
  // here, and a server only accepts a first flight without an Initial when 0-RTT is allowed
  (void) result;
  if (m_quicl4->Is0RTTHandshakeAllowed ())
    {
      NS_LOG_INFO (
        "CONNECTION AUTHENTICATED Client found the Server " << InetSocketAddress::ConvertFrom (address).GetIpv4 () << " port " << InetSocketAddress::ConvertFrom (address).GetPort () << " in authenticated list");
      // connect the underlying UDP socket
      m_quicl4->UdpConnect (address, this);
      return DoFastConnect ();
    }
  else
    {
      NS_LOG_INFO (
        "CONNECTION not authenticated: cannot perform 0-RTT Handshake");
      // connect the underlying UDP socket
      m_quicl4->UdpConnect (address, this);
      return DoConnect ();
    }

}

/* Inherit from Socket class: Invoked by upper-layer application */
int
QuicSocketBase::Send (Ptr<Packet> p, uint32_t flags)
{
  NS_LOG_FUNCTION (this << flags);
  int data = 0;

  if (m_drainingPeriodEvent.IsPending ())
    {
      NS_LOG_INFO ("Socket in draining state, cannot send packets");
      return 0;
    }

  // The flags carry the RFC 9000 stream id (0 is the first stream a client opens)
  data = SendOnStream (p, flags);
  return data;
}

int
QuicSocketBase::SendOnStream (Ptr<Packet> p, uint64_t streamId)
{
  // Like msquic, streams are opened and used once the connection is established: writes made while
  // the handshake is running wait for it
  if (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR)
    {
      // the writes that wait are bounded by the send buffer, like any other write
      if (m_pendingWriteBytes + p->GetSize () > m_txBuffer->Available ())
        {
          m_errno = ERROR_MSGSIZE;
          return -1;
        }
      m_pendingWriteBytes += p->GetSize ();
      m_pendingWrites.push_back (std::make_pair (p, streamId));
      return p->GetSize ();
    }
  return m_quicl5->DispatchSend (p, streamId);
}

int
QuicSocketBase::Send (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this);

  if (m_drainingPeriodEvent.IsPending ())
    {
      NS_LOG_INFO ("Socket in draining state, cannot send packets");
      return 0;
    }

  // The default stream is the first bidirectional stream this endpoint opens
  return SendOnStream (p, m_isServerSide ? 1 : 0);
}

int
QuicSocketBase::AppendingTx (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);

  if (m_socketState != IDLE)
    {
      bool done = m_txBuffer->Add (frame);
      if (!done)
        {
          NS_LOG_INFO ("Exceeding Socket Tx Buffer Size");
          m_errno = ERROR_MSGSIZE;
        }
      else
        {
          uint32_t win = AvailableWindow ();
          NS_LOG_DEBUG (
            "Added packet to the buffer - txBufSize = " << m_txBuffer->AppSize ()
                                                        << " AvailableWindow = " << win << " state " << QuicStateName[m_socketState]);
        }


      if (m_socketState != IDLE)
        {
          if (!m_sendPendingDataEvent.IsPending ())
            {
              m_sendPendingDataEvent = Simulator::Schedule (
                TimeStep (1), &QuicSocketBase::SendPendingData, this,
                m_connected);
            }
        }
      if (done)
        {
          return frame->GetSize ();
        }
      return -1;
    }
  else
    {

      NS_ABORT_MSG ("Sending in state" << QuicStateName[m_socketState]);
      return -1;
    }
}

uint32_t
QuicSocketBase::SendPendingData (bool withAck)
{
  NS_LOG_FUNCTION (this << withAck);

  // the window may have shrunk since the tolerance was raised: the peer must keep acknowledging
  // several times per round trip
  uint32_t toleranceLimit = AckToleranceLimit ();
  if (m_peerAckTolerance > toleranceLimit)
    {
      UpdatePeerAckTolerance ((uint8_t) toleranceLimit);
    }

  if (m_txBuffer->AppSize () == 0)
    {
      if (m_closeOnEmpty && !m_quicl5->HasPendingStreamData () && m_txBuffer->BytesInFlight () == 0)
        {
          // closing state (RFC 9000 s10.2): one CONNECTION_CLOSE, then incoming packets are discarded
          m_closeOnEmpty = false;
          m_drainingPeriodEvent.Cancel ();
          ScheduleCloseAndSendConnectionClosePacket ();
        }
      NS_LOG_INFO ("Nothing to send");
      return false;
    }

  uint32_t nPacketsSent = 0;

  // prioritize stream 0
  while (m_txBuffer->GetNumFrameStream0InBuffer () > 0)
    {

      NS_LOG_DEBUG ("Send a frame for stream 0");
      SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
      NS_LOG_INFO ("SN " << m_tcb->m_nextTxSequence);

      uint32_t win = AvailableWindow ();
      uint32_t connWin = ConnectionWindow ();
      uint32_t bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "BEFORE stream 0 Available Window " << win
                                            << " Connection RWnd " << connWin
                                            << " BytesInFlight " << bytesInFlight
                                            << " BufferedSize " << m_txBuffer->AppSize ()
                                            << " MaxPacketSize " << GetSegSize ());

      if (SendDataPacket (next, 0, m_queue_ack) == (uint32_t) -1)
        {
          // draining: the frame stays queued and nothing can leave, so stop instead of trying forever
          break;
        }

      win = AvailableWindow ();
      connWin = ConnectionWindow ();
      bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "AFTER stream 0 Available Window " << win
                                           << " Connection RWnd " << connWin
                                           << " BytesInFlight " << bytesInFlight
                                           << " BufferedSize " << m_txBuffer->AppSize ()
                                           << " MaxPacketSize " << GetSegSize ());

      ++nPacketsSent;
    }
  uint32_t availableWindow = AvailableWindow ();
  if (availableWindow > 0 and m_txBuffer->AppSize () > 0)
    {
      BeginSendFlush ();
    }

  while (availableWindow > 0 and m_txBuffer->AppSize () > 0)
    {
      // check draining period
      if (m_drainingPeriodEvent.IsPending ())
        {
          NS_LOG_INFO ("Draining period: no packets can be sent");
          return false;
        }

      // msquic QuicSendFlush: a flush ends after QUIC_MAX_DATAGRAMS_PER_SEND datagrams; being limited
      // by scheduling rather than by the window, it hints the peer to expect a longer batch
      if (nPacketsSent >= kMaxDatagramsPerSend)
        {
          uint32_t target = std::min<uint32_t> (kMaxDatagramsPerSend + 1, AckToleranceLimit ());
          if (target > m_peerAckTolerance)
            {
              UpdatePeerAckTolerance ((uint8_t) target);
            }
          if (!m_sendPendingDataEvent.IsPending ())
            {
              m_sendPendingDataEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendPendingData, this, withAck);
            }
          break;
        }

      // msquic pacing: the chunk allowance of this flush is used up, continue 1 ms later
      if (m_flushAllowance == 0)
        {
          NS_LOG_INFO ("Pacing allowance exhausted - next chunk in 1 ms");
          if (!m_pacingTimer.IsRunning ())
            {
              m_pacingTimer.Schedule (MilliSeconds (1));
            }
          break;
        }

      // check the state of the socket!
      if (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR)
        {
          NS_LOG_INFO ("CONNECTING_CLT and CONNECTING_SVR state; no data to transmit");
          break;
        }

      uint32_t availableData = m_txBuffer->AppSize ();

      if (availableData < availableWindow and !m_closeOnEmpty)
        {
          NS_LOG_INFO ("Ask the app for more data before trying to send");
          NotifySend (GetTxAvailable ());
        }

      // msquic amplification protection: a path that is not validated yet takes at most three times
      // what the peer sent on it; a packet is cut down to what is left (QuicPathSetAllowance). While a challenge
      // is pending on the path, data leaves the reserve alone: it is what repeats a lost challenge (see
      // SendPathChallenge), and nothing else replenishes the allowance if the peer has nothing to send
      uint32_t s = GetSegSize ();
      if (!m_paths.empty () && !m_paths.front ().validated)
        {
          uint64_t room = m_paths.front ().allowance;
          if (m_paths.front ().sendChallenge)
            {
              room = room > kChallengeReserve ? room - kChallengeReserve : 0;
            }
          if (room < kMinSendAllowance)
            {
              NS_LOG_INFO ("Blocked by amplification protection");
              break;
            }
          s = (uint32_t) std::min<uint64_t> (s, room);
        }

      SequenceNumber32 next = ++m_tcb->m_nextTxSequence;

      // msquic (CubicCongestionControlCanSend): a packet may go out whenever bytes in flight are
      // below the window, even if the packet then exceeds it

      uint32_t win = AvailableWindow ();
      uint32_t connWin = ConnectionWindow ();
      uint32_t bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "BEFORE Available Window " << win
                                   << " Connection RWnd " << connWin
                                   << " BytesInFlight " << bytesInFlight
                                   << " BufferedSize " << m_txBuffer->AppSize ()
                                   << " MaxPacketSize " << GetSegSize ());

      // uint32_t sz =
      SendDataPacket (next, s, withAck);

      win = AvailableWindow ();
      connWin = ConnectionWindow ();
      bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "AFTER Available Window " << win
                                  << " Connection RWnd " << connWin
                                  << " BytesInFlight " << bytesInFlight
                                  << " BufferedSize " << m_txBuffer->AppSize ()
                                  << " MaxPacketSize " << GetSegSize ());

      ++nPacketsSent;

      availableWindow = AvailableWindow ();
    }

  if (nPacketsSent > 0)
    {
      NS_LOG_INFO ("SendPendingData sent " << nPacketsSent << " packets");
      // the packets left the transmit buffer: streams that a full buffer turned away can push frames again
      m_quicl5->OnSocketTxSpace ();
    }
  else
    {
      NS_LOG_INFO ("SendPendingData no packets sent");
    }

  return nPacketsSent;
}

void
QuicSocketBase::SetSegSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  NS_ABORT_MSG_UNLESS (m_socketState == IDLE || m_tcb->m_segmentSize == size,
                       "Cannot change segment size dynamically.");

  m_tcb->m_segmentSize = size;
  // Update minimum congestion window
  m_tcb->m_kMinimumWindow = 2 * size;
  // RFC 9002 §7.2: initial_cwnd = min(10*max_datagram_size, max(14720, 2*max_datagram_size))
  uint32_t rfcInitialCwnd = std::min (10 * size, std::max ((uint32_t)14720, 2 * size));
  m_tcb->m_initialCWnd = rfcInitialCwnd;
}

uint32_t
QuicSocketBase::GetSegSize (void) const
{
  return m_tcb->m_segmentSize;
}

void
QuicSocketBase::MaybeQueueAck ()
{
  NS_LOG_FUNCTION (this);
  ++m_numPacketsReceivedSinceLastAckSent;
  NS_LOG_INFO ("m_numPacketsReceivedSinceLastAckSent " << m_numPacketsReceivedSinceLastAckSent << " m_queue_ack " << m_queue_ack);

  if (m_receivedPacketNumbers.Empty ())
    {
      NS_LOG_INFO ("Nothing to ACK");
      m_queue_ack = false;
      return;
    }

  // msquic QuicAckTrackerAckPacket: send the ACK at once when an IMMEDIATE_ACK frame arrived, when ACK
  // delay is disabled, when PacketTolerance ack-eliciting packets are pending, or when a new largest
  // packet leaves a hole at or above the reordering threshold; otherwise start the delayed ACK timer.
  bool immediate = m_immediateAckRequested
    || m_tcb->m_kDelayedAckTimeout.IsZero ()
    || m_numPacketsReceivedSinceLastAckSent >= m_ackTolerance
    || HasReceivedMissing ();
  m_immediateAckRequested = false;

  if (immediate)
    {
      NS_LOG_INFO ("immediately send ACK");
      m_queue_ack = true;
      if (!m_sendAckEvent.IsPending ())
        {
          m_sendAckEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendAck, this);
        }
    }
  else if (!m_queue_ack && !m_delAckEvent.IsPending ())
    {
      NS_LOG_INFO ("Schedule a delayed ACK");
      m_delAckEvent = Simulator::Schedule (m_tcb->m_kDelayedAckTimeout, &QuicSocketBase::SendAck, this);
    }
}

bool
QuicSocketBase::HasReceivedMissing ()
{
  // Port of msquic QuicAckTrackerDidHitReorderingThreshold (0 disables it)
  uint32_t threshold = m_ackReorderingThreshold;
  if (threshold == 0 || m_receivedPacketNumbers.Empty ())
    {
      return false;
    }
  const auto &ranges = m_receivedPacketNumbers.Ranges ();
  if (ranges.size () < 2 || m_latestRecvPn != m_receivedPacketNumbers.Largest ())
    {
      return false;
    }
  uint32_t largestUnacked = m_receivedPacketNumbers.Largest ();
  uint32_t smallestTracked = ranges.begin ()->first;
  uint32_t largestReported = (m_largestPnAckedByUs >= smallestTracked + threshold)
    ? m_largestPnAckedByUs - threshold + 1
    : smallestTracked;
  // walk the ranges from the newest down, looking at the holes above the largest reported packet
  for (auto it = ranges.rbegin (); std::next (it) != ranges.rend (); ++it)
    {
      if (largestReported >= it->first)
        {
          return false;
        }
      uint32_t previousSmallestMissing = std::next (it)->second + 1;
      if (largestReported > previousSmallestMissing)
        {
          previousSmallestMissing = largestReported;
        }
      if (largestUnacked - previousSmallestMissing >= threshold)
        {
          return true;
        }
    }
  return false;
}

void
QuicSocketBase::SendAck ()
{
  NS_LOG_FUNCTION (this);
  m_delAckEvent.Cancel ();
  m_sendAckEvent.Cancel ();
  m_queue_ack = false;

  m_numPacketsReceivedSinceLastAckSent = 0;

  MaybeUpdateDestCid ();
  m_lastPacketSent = Simulator::Now ();
  Ptr<Packet> p = Create<Packet> ();
  p->AddAtEnd (OnSendingAckFrame ());
  SequenceNumber32 packetNumber = ++m_tcb->m_nextTxSequence;

  QuicHeader head;

  head = QuicHeader::CreateShort (GetDestCid (), packetNumber,
                                  !m_omit_connection_id, m_keyPhase, m_spinBit);

  // if (m_socketState == CONNECTING_SVR)
  //   {
  //     m_connected = true;
  //     head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
  //                                         packetNumber);
  //   }
  // else if (m_socketState == CONNECTING_CLT)
  //   {
  //     head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
  //   }
  // else if (m_socketState == OPEN)
  //   {
  //     if (!m_connected and !m_quicl4->Is0RTTHandshakeAllowed ())
  //       {
  //         m_connected = true;
  //         head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
  //                                             packetNumber);
  //       }
  //     else if (!m_connected and m_quicl4->Is0RTTHandshakeAllowed ())
  //       {
  //         head = QuicHeader::Create0RTT (m_connectionId, m_vers,
  //                                        packetNumber);
  //         m_connected = true;
  //         m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
  //                                                   QuicHeader::PHASE_ZERO :
  //                                               m_keyPhase =
  //                                                   QuicHeader::PHASE_ONE;
  //       }
  //     else
  //       {
  //         head = QuicHeader::CreateShort (GetDestCid (), packetNumber,
  //                                         !m_omit_connection_id, m_keyPhase);
  //       }
  //   }
  // else
  //   {
  //     NS_FATAL_ERROR("ACK not possible in this state");
  //   }

  m_txBuffer->UpdateAckSent (packetNumber, p->GetSerializedSize () + head.GetSerializedSize ());

  NS_LOG_INFO ("Send ACK packet with header " << head);
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);
}

void
QuicSocketBase::SendStreamsBlockedFrame (uint64_t streamLimit, bool bidirectional)
{
  NS_LOG_FUNCTION (this << streamLimit << bidirectional);

  // once per limit (RFC 9000 s4.6); the frame is retransmitted like any other control frame
  uint64_t &reported = m_streamsBlockedAt[bidirectional ? 0 : 1];
  if (reported == streamLimit)
    {
      return;
    }
  reported = streamLimit;
  QuicSubheader sb = QuicSubheader::CreateStreamIdBlocked (streamLimit);
  if (!bidirectional)
    {
      sb.SetFrameType (QuicSubheader::STREAMS_BLOCKED_UNI);
    }
  Ptr<Packet> p = Create<Packet> (0);
  p->AddHeader (sb);
  NS_LOG_INFO ("Send STREAMS_BLOCKED frame (limit=" << streamLimit << ", bidi=" << bidirectional << ")");
  AppendingTx (p);
}

void
QuicSocketBase::GrantPeerStream (bool bidirectional)
{
  uint32_t &limit = bidirectional ? m_initial_max_stream_id_bidi : m_initial_max_stream_id_uni;
  ++limit;
  QuicSubheader ms = QuicSubheader::CreateMaxStreamId (limit);
  if (!bidirectional)
    {
      ms.SetFrameType (QuicSubheader::MAX_STREAMS_UNI);
    }
  Ptr<Packet> p = Create<Packet> (0);
  p->AddHeader (ms);
  NS_LOG_INFO ("Send MAX_STREAMS frame (bidi=" << bidirectional << ", limit=" << limit << ")");
  AppendingTx (p);
}

uint32_t
QuicSocketBase::SendDataPacket (SequenceNumber32 packetNumber,
                                uint32_t maxSize, bool withAck)
{
  NS_LOG_FUNCTION (this << packetNumber << maxSize << withAck);

  if (m_drainingPeriodEvent.IsPending ())
    {
      NS_LOG_INFO ("Draining period event running");
      return -1;
    }

  if (!m_idleTimeoutEvent.IsPending ()
      && m_socketState != CLOSING && m_socketState != IDLE)
    {
      ArmIdleTimer ();
    }

  Ptr<Packet> p;
  Ptr<Packet> ackFrame;

  if (m_txBuffer->GetNumFrameStream0InBuffer () > 0)
    {
      p = m_txBuffer->NextStream0Sequence (packetNumber);
      NS_ABORT_MSG_IF (p == nullptr, "No packet for stream 0 in the buffer!");
    }
  else
    {
      NS_LOG_LOGIC (
        this << " SendDataPacket - sending packet " << packetNumber.GetValue () << " of size " << maxSize << " at time " << Simulator::Now ().GetSeconds ());
      // The ACK frame travels in the same datagram: leave room for it, or the datagram goes over the
      // segment size, gets fragmented by IP, and a lost fragment costs the whole packet
      uint32_t room = maxSize;
      if (withAck && !m_receivedPacketNumbers.Empty ())
        {
          ackFrame = OnSendingAckFrame ();
          if (ackFrame->GetSize () < maxSize)
            {
              room = maxSize - ackFrame->GetSize ();
            }
        }
      p = m_txBuffer->NextSequence (room, packetNumber);
    }

  uint32_t sz = p->GetSize ();

  // check whether the connection is appLimited, i.e. not enough data to fill a packet
  if (sz < maxSize and m_txBuffer->AppSize () == 0 and m_tcb->m_bytesInFlight.Get () < m_tcb->m_cWnd)
    {
      NS_LOG_LOGIC ("Connection is Application-Limited. sz = " << sz << " < maxSize = " << maxSize);
      auto appLimitedVal2 = m_tcb->m_delivered + m_tcb->m_bytesInFlight.Get ();
      m_tcb->m_appLimitedUntil = appLimitedVal2 ? appLimitedVal2 : 1U;
    }

  ConsumeSendAllowance (sz);

  bool isAckOnly = ((sz == 0) & (withAck));

  if (withAck && !m_receivedPacketNumbers.Empty ())
    {
      // p is the very packet kept in the sent list for retransmission: appending the ACK to it would
      // make the stored copy carry an ACK frame that later gets split and resent as stream data
      p = p->Copy ();
      p->AddAtEnd (ackFrame ? ackFrame : OnSendingAckFrame ());
    }


  QuicHeader head;

  if (m_socketState == CONNECTING_SVR)
    {
      m_connected = true;
      head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                          packetNumber);
    }
  else if (m_socketState == CONNECTING_CLT)
    {
      head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
    }
  else if (m_socketState == OPEN)
    {
      if (!m_connected and !m_quicl4->Is0RTTHandshakeAllowed ())
        {
          m_connected = true;
          head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                              packetNumber);
        }
      else if (!m_connected and m_quicl4->Is0RTTHandshakeAllowed ())
        {
          head = QuicHeader::Create0RTT (m_connectionId, m_vers,
                                         packetNumber);
          m_connected = true;
          m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
            QuicHeader::PHASE_ZERO :
            m_keyPhase =
              QuicHeader::PHASE_ONE;
        }
      else
        {
          head = QuicHeader::CreateShort (GetDestCid (), packetNumber,
                                          !m_omit_connection_id, m_keyPhase, m_spinBit);
        }
    }
  else if (IsFlushingOnClose ())
    {
      // Close() was called: keep sending buffered data before the connection is closed
      head = QuicHeader::CreateShort (GetDestCid (), packetNumber,
                                      !m_omit_connection_id, m_keyPhase, m_spinBit);
    }
  else
    {
      // 0 bytes sent - the socket is closed!
      return 0;
    }

  // RFC 9000 §8: anti-amplification — server must not send > 3× received bytes until address validated
  if (!m_peerAddressValidated && m_socketState == CONNECTING_SVR)
    {
      uint64_t pktSize = p->GetSize () + head.GetSerializedSize ();
      if (m_bytesSentPreValidation + pktSize > 3 * m_bytesReceivedPreValidation
          && m_bytesReceivedPreValidation > 0)
        {
          NS_LOG_WARN ("Anti-amplification limit reached: sent=" << m_bytesSentPreValidation
                       << " would-be=" << (m_bytesSentPreValidation + pktSize)
                       << " 3xreceived=" << 3 * m_bytesReceivedPreValidation << " — holding packet");
          return 0;
        }
      m_bytesSentPreValidation += pktSize;
    }

  NS_LOG_INFO ("SendDataPacket of size " << p->GetSize ());
  if (!m_paths.empty () && !m_paths.front ().validated)
    {
      uint64_t wire = p->GetSize () + head.GetSerializedSize ();
      m_paths.front ().allowance = (wire >= m_paths.front ().allowance) ? 0 : m_paths.front ().allowance - wire;
    }
  m_lastPacketSent = Simulator::Now ();
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);
  NotifyDataSent (sz);

  m_txBuffer->UpdatePacketSent (packetNumber, sz);

  if (!m_quicCongestionControlLegacy)
    {
      DynamicCast<QuicCongestionOps> (m_congestionControl)->OnPacketSent (
        m_tcb, packetNumber, isAckOnly);
    }
  if (!isAckOnly)
    {
      m_tcb->m_timeOfLastAckElicitingSent = Simulator::Now ();
      SetReTxTimeout ();
    }

  return sz;
}

void
QuicSocketBase::SetReTxTimeout ()
{
  //TODO check for special packets
  NS_LOG_FUNCTION (this);

  // RFC 9002 §5.4 #24: client SHOULD arm PTO even when no in-flight if handshake unconfirmed.
  // Cancel the alarm only when there is nothing in flight AND handshake is already confirmed.
  if (BytesInFlight () == 0 && m_tcb->m_handshakeConfirmed)
    {
      NS_LOG_INFO ("No in-flight bytes and handshake confirmed; cancelling loss alarm");
      m_tcb->m_lossDetectionAlarm.Cancel ();
      return;
    }

  // Note: m_lossTime is set by OnAckUpdate when ACK gaps suggest time-based loss.
  // Do NOT speculatively set m_lossTime here — that would bypass PTO on every call.

  // RFC 9002 s6.2.1: the PTO is measured from the send time of the latest ack-eliciting packet, not from
  // the moment the timer is (re)armed
  Time sentAt = m_tcb->m_timeOfLastAckElicitingSent.IsStrictlyPositive ()
                ? m_tcb->m_timeOfLastAckElicitingSent
                : Simulator::Now ();
  Time fireAt;
  // Handshake packets are outstanding
  if (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Connecting, set alarm");
      // RFC 9002 s6.2.1 / s6.2.2: srtt + max (4 * rttvar, kGranularity), max_ack_delay is 0 for the
      // Initial and Handshake packet number spaces; kInitialRtt stands in until the first sample
      fireAt = sentAt + ProbeTimeout (false) * (1u << std::min (m_tcb->m_handshakeCount, 30u));
      m_tcb->m_alarmType = 0;
    }
  else if (m_tcb->m_lossTime != Seconds (0))
    {
      NS_LOG_INFO ("Time-threshold loss detection timer");
      // RFC 9002 §6.1.2: fire at earliest time-based loss deadline
      fireAt = m_tcb->m_lossTime;
      m_tcb->m_alarmType = 1;
    }
  else
    {
      // RFC 9002 §6.2.7: MUST NOT arm PTO if anti-amplification limit would block sending
      if (!m_peerAddressValidated && m_socketState == CONNECTING_SVR
          && m_bytesReceivedPreValidation > 0
          && m_bytesSentPreValidation >= 3 * m_bytesReceivedPreValidation)
        {
          NS_LOG_INFO ("PTO not armed: server at anti-amplification limit (RFC 9002 §6.2.7)");
          return;
        }

      // RFC 9002 §6.2: Probe Timeout (PTO) - replaces TLP + RTO cascade
      NS_LOG_LOGIC ("PTO");
      fireAt = sentAt + ProbeTimeout (true) * (1u << std::min (m_tcb->m_rtoCount, 30u));
      m_tcb->m_alarmType = 2;
    }
  Time alarmDuration = fireAt - Simulator::Now ();
  if (alarmDuration.IsNegative ())
    {
      alarmDuration = Seconds (0);
    }
  else if (m_tcb->m_alarmType == 1 && alarmDuration.IsZero ())
    {
      alarmDuration = MilliSeconds (1);
    }
  NS_LOG_INFO ("Schedule ReTxTimeout at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + alarmDuration).GetSeconds ());
  NS_LOG_INFO ("Alarm after " << alarmDuration.GetSeconds () << " seconds");
  m_tcb->m_lossDetectionAlarm.Cancel ();
  m_tcb->m_lossDetectionAlarm = Simulator::Schedule (alarmDuration,
                                                     &QuicSocketBase::ReTxTimeout, this);
  m_tcb->m_nextAlarmTrigger = Simulator::Now () + alarmDuration;
}

Time
QuicSocketBase::ProbeTimeout (bool withMaxAckDelay) const
{
  // RFC 9002 s6.2.1: smoothed_rtt + max (4 * rttvar, kGranularity) + max_ack_delay; before the first RTT
  // sample smoothed_rtt is kInitialRtt and rttvar is kInitialRtt / 2 (RFC 9002 s6.2.2)
  Time srtt = m_tcb->m_smoothedRtt;
  Time var = m_tcb->m_rttVar;
  if (srtt.IsZero ())
    {
      srtt = m_tcb->m_kDefaultInitialRtt;
      var = srtt / 2;
    }
  Time pto = srtt + std::max (4 * var, MilliSeconds (1));
  if (withMaxAckDelay)
    {
      pto += m_tcb->m_maxAckDelay;
    }
  return pto;
}

void
QuicSocketBase::UpdateLostSpanState (const std::vector<Ptr<QuicSocketTxItem> > &lostPackets)
{
  m_tcb->m_lostSpanHasAck = false;
  if (lostPackets.size () < 2)
    {
      return;
    }
  Time oldest = lostPackets.front ()->m_lastSent;
  Time newest = oldest;
  for (auto &pkt : lostPackets)
    {
      oldest = std::min (oldest, pkt->m_lastSent);
      newest = std::max (newest, pkt->m_lastSent);
    }
  m_tcb->m_lostSpanHasAck = m_txBuffer->HasAckedPacketBetween (oldest, newest);
}

void
QuicSocketBase::CheckSpuriousLosses (uint32_t largest, const std::vector<uint32_t> &blocks,
                                     const std::vector<uint32_t> &gaps, uint32_t ackFloor)
{
  if (m_declaredLost.empty () || m_quicCongestionControlLegacy)
    {
      return;
    }
  std::vector<uint32_t> ups = blocks;
  ups.insert (ups.begin (), largest);
  Ptr<QuicCongestionOps> cc = DynamicCast<QuicCongestionOps> (m_congestionControl);
  for (auto it = m_declaredLost.begin (); it != m_declaredLost.end ();)
    {
      bool acked = false;
      for (size_t i = 0; i < ups.size () && !acked; ++i)
        {
          bool aboveGap = (i >= gaps.size ()) ? (*it >= ackFloor) : (*it > gaps[i]);
          acked = (*it <= ups[i]) && aboveGap;
        }
      if (acked)
        {
          NS_LOG_INFO ("Packet " << *it << " declared lost was acknowledged (spurious)");
          m_spuriousLossTrace (*it);
          cc->OnSpuriousLoss (m_tcb, SequenceNumber32 (*it));
          it = m_declaredLost.erase (it);
        }
      else
        {
          ++it;
        }
    }
}

void
QuicSocketBase::DoRetransmit (std::vector<Ptr<QuicSocketTxItem> > lostPackets, bool exempt)
{
  NS_LOG_FUNCTION (this);
  for (auto &p : lostPackets)
    {
      m_declaredLost.insert (p->m_packetNumber.GetValue ());
    }
  while (m_declaredLost.size () > 1024)
    {
      m_declaredLost.erase (m_declaredLost.begin ());
    }
  // Get packets to retransmit
  SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
  uint32_t toRetx = m_txBuffer->Retransmission (next);
  NS_LOG_INFO (toRetx << " bytes to retransmit");
  NS_LOG_DEBUG ("Send the retransmitted frame");
  uint32_t win = AvailableWindow ();
  uint32_t connWin = ConnectionWindow ();
  uint32_t bytesInFlight = BytesInFlight ();
  NS_LOG_DEBUG (
    "BEFORE Available Window " << win
                               << " Connection RWnd " << connWin
                               << " BytesInFlight " << bytesInFlight
                               << " BufferedSize " << m_txBuffer->AppSize ()
                               << " MaxPacketSize " << GetSegSize ());

  // Send the retransmitted data, respecting the congestion window
  // (allow at least one segment to make progress even if window is exceeded)
  // Never build a datagram larger than one segment: a single large packet would be fragmented
  // by IP and almost never survive. What does not fit stays queued for SendPendingData.
  uint32_t remaining = toRetx;
  bool first = true;
  while (remaining > 0)
    {
      win = AvailableWindow ();
      if (!first && win == 0 && !exempt)
        {
          break;
        }
      uint32_t sendSize = std::min (remaining, GetSegSize ());
      if (win > 0 && !exempt)
        {
          sendSize = std::min (sendSize, win);
        }
      SequenceNumber32 pn = next;
      if (!first)
        {
          pn = ++m_tcb->m_nextTxSequence;
        }
      first = false;
      NS_LOG_INFO ("Retransmitted packet, next sequence number " << m_tcb->m_nextTxSequence);
      uint32_t sent = SendDataPacket (pn, sendSize, m_connected);
      if (sent == 0 || sent == (uint32_t) -1)
        {
          break;
        }
      remaining -= std::min (remaining, sent);
    }
}

void
QuicSocketBase::EnterDraining ()
{
  // RFC 9000 s10.2.2: after a CONNECTION_CLOSE from the peer nothing more is sent; the state is kept for three
  // PTOs so that late packets of the connection are absorbed instead of provoking a stateless reset
  m_closeOnEmpty = false;
  m_drainingPeriodEvent.Cancel ();
  m_tcb->m_lossDetectionAlarm.Cancel ();
  m_idleTimeoutEvent.Cancel ();
  SetState (CLOSING);
  m_drainingPeriodEvent = Simulator::Schedule (3 * ProbeTimeout (true), &QuicSocketBase::DoClose, this);
  // the application hears of the close right away, outside the frame being processed
  Simulator::ScheduleNow (&QuicSocketBase::NotifyClosedByPeer, this);
}

void
QuicSocketBase::NotifyClosedByPeer ()
{
  if (!m_closeNotified)
    {
      m_closeNotified = true;
      NotifyNormalClose ();
    }
}

void
QuicSocketBase::NotePacketReceived (uint32_t packetNumber)
{
  m_receivedPacketNumbers.Add (packetNumber);
  m_latestRecvPn = packetNumber;
  if (m_receivedPacketNumbers.Largest () == packetNumber)
    {
      m_largestRecvTime = Simulator::Now ();   // the ack delay of RFC 9000 s13.2.5 counts from this packet
    }
}

void
QuicSocketBase::ArmIdleTimer ()
{
  m_idleTimeoutEvent.Cancel ();
  if (m_idleTimeout.Get ().IsZero ())
    {
      return;   // RFC 9000 s10.1: no idle timeout negotiated
    }
  // RFC 9000 s10.1: the idle timeout is at least three times the PTO, so that loss recovery gets its say first
  Time timeout = std::max (m_idleTimeout.Get (), 3 * ProbeTimeout (true));
  NS_LOG_LOGIC (this << " idle timer set at time " << Simulator::Now ().GetSeconds () << " to expire at time "
                     << (Simulator::Now () + timeout).GetSeconds ());
  m_idleTimeoutEvent = Simulator::Schedule (timeout, &QuicSocketBase::Close, this);
}

bool
QuicSocketBase::IdleTimerArmed () const
{
  // a disabled idle timer (max_idle_timeout 0) never has an event, but an open connection still counts as armed:
  // Close () tells an application close (timer armed) from an idle expiry (timer fired) by this
  return m_idleTimeoutEvent.IsPending ()
         || (m_idleTimeout.Get ().IsZero () && m_socketState == OPEN);
}

void
QuicSocketBase::ReTxTimeout ()
{
  if (Simulator::Now () < m_tcb->m_nextAlarmTrigger)
    {
      NS_LOG_INFO ("Canceled alarm");
      return;
    }
  if ((m_socketState == CLOSING && !IsFlushingOnClose ()) || m_socketState == IDLE)
    {
      NS_LOG_INFO ("ReTxTimeout: socket in CLOSING/IDLE state, ignoring");
      return;
    }
  NS_LOG_FUNCTION (this);
  m_tcb->m_ptoCountForLoss = m_tcb->m_rtoCount;
  NS_LOG_INFO ("ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ());
  // Handshake packets are outstanding)
  if (m_tcb->m_alarmType == 0 && (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR))
    {
      // Handshake retransmission alarm.
      // RFC 9002 s6.2.2: retransmit the outstanding handshake data (stream 0)
      m_txBuffer->ResetSentList (0);
      std::vector<Ptr<QuicSocketTxItem> > lostHandshake = m_txBuffer->DetectLostPackets ();
      m_tcb->m_handshakeCount++;
      if (!lostHandshake.empty ())
        {
          DoRetransmit (lostHandshake);
        }
    }
  else if (m_tcb->m_alarmType == 1 && m_tcb->m_lossTime != Seconds (0))
    {
      m_txBuffer->DetectTimeLoss (m_tcb, m_tcb->m_largestAckedPacket.GetValue ());
      std::vector<Ptr<QuicSocketTxItem> > lostPackets = m_txBuffer->DetectLostPackets ();
      NS_LOG_INFO ("RTO triggered: early retransmit");
      if (lostPackets.empty ())
        {
          SetReTxTimeout ();
          return;
        }
      // Early retransmit or Time Loss Detection.
      if (m_quicCongestionControlLegacy)
        {
          // TCP early retransmit logic [RFC 5827]: enter recovery (RFC 6675, Sec. 5)
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY)
            {
              m_tcb->m_congState = TcpSocketState::CA_RECOVERY;
              m_tcb->m_cWnd = m_tcb->m_ssThresh;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_RECOVERY);
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                m_tcb, BytesInFlight ());
            }
        }
      else
        {
          Ptr<QuicCongestionOps> cc = dynamic_cast<QuicCongestionOps*> (&(*m_congestionControl));
          UpdateLostSpanState (lostPackets);
          cc->OnPacketsLost (m_tcb, lostPackets);
        }
      // Retransmit all lost packets immediately
      DoRetransmit (lostPackets);
    }
  else if (m_tcb->m_alarmType == 2)
    {
      // RFC 9002 §6.2.4: Probe Timeout — send at least one ack-eliciting packet
      if (m_tcb->m_rtoCount == 0)
        {
          m_tcb->m_largestSentBeforeRto = m_tcb->m_highTxMark;
        }
      NS_LOG_INFO ("PTO triggered (ptoCount=" << m_tcb->m_rtoCount << ")");
      m_pacingTimer.Cancel ();

      // msquic QuicLossDetectionScheduleProbe: 2 ack-eliciting packets, exempt from the congestion
      // window: fresh data first, then the oldest outstanding data, then a PING.
      uint32_t probes = 2;
      while (probes > 0 && m_txBuffer->AppSize () > 0)
        {
          SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
          SendDataPacket (next, GetSegSize (), m_connected);
          probes--;
        }
      if (probes > 0)
        {
          // PTO is not a congestion event (RFC 9002 s6.2.4): no OnPacketsLost here
          std::vector<Ptr<QuicSocketTxItem> > oldest = m_txBuffer->MarkOldestAsLost (probes);
          if (!oldest.empty ())
            {
              DoRetransmit (oldest, true);
              probes -= std::min<uint32_t> (probes, oldest.size ());
            }
        }
      if (probes > 0)
        {
          // RFC 9002 s6.2.4: nothing left to resend, so the probe is a PING: ack-eliciting without data of
          // its own (an empty packet would count as "only an ACK" and the peer would not have to answer)
          SendControlFrame (QuicSubheader::CreatePing ());
          SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
          SendDataPacket (next, GetSegSize (), m_connected);
          probes--;
        }
      if (m_tcb->m_rtoCount == 0)
        {
          m_ptoEpisodeStart = Now ();
        }
      m_tcb->m_rtoCount++;
      // the backoff doubled: measure the next PTO from the last probe
      SetReTxTimeout ();

      // RFC 9002 §6.2.1: SHOULD abandon connection after repeated consecutive PTOs
      // with no new ACK.  m_rtoCount is reset in OnReceivedAckFrame whenever a new
      // ACK arrives, so a large value means the peer is truly unreachable.
      if (Now () - m_ptoEpisodeStart >= m_disconnectTimeout
          && (m_socketState == OPEN || IsFlushingOnClose ()))
        {
          NS_LOG_WARN ("QuicSocketBase: disconnect timeout (" << m_disconnectTimeout
                       << ") reached — connection unreachable, closing");
          // Cancel timers before state change to prevent re-entry
          m_tcb->m_lossDetectionAlarm.Cancel ();
          m_idleTimeoutEvent.Cancel ();
          SetState (CLOSING);
          // Notify application: fires HandlePeerError → ConnectionCallback(false)
          m_closeNotified = true;
          NotifyErrorClose ();
          // Schedule final teardown; ScheduleNow avoids re-entrancy from callbacks
          Simulator::ScheduleNow (&QuicSocketBase::DoClose, this);
          return;
        }
    }
}

uint32_t
QuicSocketBase::AvailableWindow () const
{
  NS_LOG_FUNCTION (this);

  NS_LOG_DEBUG ("m_max_data " << m_max_data << " m_tcb->m_cWnd.Get () " << m_tcb->m_cWnd.Get ());
  uint32_t win = m_tcb->m_cWnd.Get ();   // Number of bytes allowed to be outstanding
  uint32_t inflight = BytesInFlight ();   // Number of outstanding bytes

  if (inflight > win)
    {
      NS_LOG_INFO (
        "InFlight=" << inflight << ", Win=" << win << " availWin=0");
      return 0;
    }

  NS_LOG_INFO (
    "InFlight=" << inflight << ", Win=" << win << " availWin=" << win - inflight);
  return win - inflight;

}

uint32_t
QuicSocketBase::ConnectionWindow () const
{
  NS_LOG_FUNCTION (this);

  uint32_t inFlight = BytesInFlight ();

  NS_LOG_INFO (
    "Returning calculated Connection: MaxData " << m_max_data << " InFlight: " << inFlight);

  (void) inFlight;
  return UINT32_MAX; // peer limits are enforced per stream, on new data only
}

uint32_t
QuicSocketBase::BytesInFlight () const
{
  NS_LOG_FUNCTION (this);

  uint32_t bytesInFlight = m_txBuffer->BytesInFlight ();

  NS_LOG_INFO ("Returning calculated bytesInFlight: " << bytesInFlight);
  m_tcb->m_bytesInFlight = bytesInFlight;
  return bytesInFlight;
}

/* Inherit from Socket class: In QuicSocketBase, it is same as Send() call */
int
QuicSocketBase::SendTo (Ptr<Packet> p, uint32_t flags, const Address &address)
{
  NS_LOG_FUNCTION (this);

  return Send (p, flags);
}

/* Inherit from Socket class: Return data to upper-layer application. Parameter flags
 is not used. Data is returned as a packet of size no larger than maxSize */
Ptr<Packet>
QuicSocketBase::Recv (uint32_t maxSize, uint32_t flags)
{
  NS_LOG_FUNCTION (this);
  NS_ABORT_MSG_IF (flags,
                   "use of flags is not supported in QuicSocketBase::Recv()");

  if (m_rxBuffer->Size () == 0 && m_socketState == CLOSING)
    {
      return Create<Packet> ();
    }
  Ptr<Packet> outPacket = m_rxBuffer->Extract (maxSize);
  return outPacket;
}

/* Inherit from Socket class: Recv and return the remote's address */
Ptr<Packet>
QuicSocketBase::RecvFrom (uint32_t maxSize, uint32_t flags,
                          Address &fromAddress)
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> packet = m_rxBuffer->Extract (maxSize);

  if (packet != nullptr && packet->GetSize () != 0)
    {
      if (m_endPoint != nullptr)
        {
          fromAddress = InetSocketAddress (m_endPoint->GetPeerAddress (), m_endPoint->GetPeerPort ());
        }
      else if (m_endPoint6 != nullptr)
        {
          fromAddress = Inet6SocketAddress (m_endPoint6->GetPeerAddress (), m_endPoint6->GetPeerPort ());
        }
      else
        {
          fromAddress = InetSocketAddress (Ipv4Address::GetZero (), 0);
        }
    }

  return packet;
}

void
QuicSocketBase::ScheduleCloseAndSendConnectionClosePacket ()
{
  m_drainingPeriodEvent.Cancel ();
  NS_LOG_LOGIC (this << " Close Schedule DoClose at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_drainingPeriodTimeout.Get ()).GetSeconds ());
  m_drainingPeriodEvent = Simulator::Schedule (m_drainingPeriodTimeout, &QuicSocketBase::DoClose, this);
  SendConnectionClosePacket (0, "Scheduled connection close - no error");
}


int
QuicSocketBase::Close (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO (this << " Close at time " << Simulator::Now ().GetSeconds ());

  if (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR)
    {
      // Data written before the handshake completes must still be flushed
      m_closeAfterHandshake = true;
      return 0;
    }

  m_receivedTransportParameters = false;

  if (IdleTimerArmed () and m_socketState != IDLE
      and m_socketState != CLOSING)   //Connection Close from application signal
    {
      SetState (CLOSING);
      if (m_flushOnClose)
        {
          m_closeOnEmpty = true;
        }
      else
        {
          ScheduleCloseAndSendConnectionClosePacket ();
        }
    }
  else if (!IdleTimerArmed () and m_socketState != CLOSING
           and m_socketState != IDLE and m_socketState != LISTENING) //Connection Close due to Idle Period termination
    {
      SetState (CLOSING);
      if (!m_closeNotified)
        {
          // msquic reports an idle timeout as a transport shutdown (QUIC_STATUS_CONNECTION_IDLE)
          m_closeNotified = true;
          NotifyErrorClose ();
        }
      m_drainingPeriodEvent.Cancel ();
      NS_LOG_LOGIC (
        this << " Close Schedule DoClose at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_drainingPeriodTimeout.Get ()).GetSeconds ());
      m_drainingPeriodEvent = Simulator::Schedule (m_drainingPeriodTimeout,
                                                   &QuicSocketBase::DoClose,
                                                   this);
    }
  else if (!IdleTimerArmed ()
           and m_drainingPeriodEvent.IsExpired () and m_socketState != CLOSING
           and m_socketState != IDLE) //close last listening sockets
    {
      NS_LOG_LOGIC (this << " Closing listening socket");
      DoClose ();
    }
  else if (!IdleTimerArmed ()
           and m_drainingPeriodEvent.IsExpired () and m_socketState == IDLE)
    {
      NS_LOG_LOGIC (this << " Has already been closed");
    }

  return 0;
}

/* Send a CONNECTION_CLOSE frame */
uint32_t
QuicSocketBase::SendConnectionClosePacket (uint16_t errorCode, std::string phrase)
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> p = Create<Packet> ();
  SequenceNumber32 packetNumber = ++m_tcb->m_nextTxSequence;

  QuicSubheader qsb = QuicSubheader::CreateConnectionClose (errorCode, phrase.c_str ());
  p->AddHeader (qsb);


  QuicHeader head;

  head = QuicHeader::CreateShort (GetDestCid (), packetNumber,
                                  !m_omit_connection_id, m_keyPhase, m_spinBit);

  NS_LOG_DEBUG ("Send Connection Close packet with header " << head);
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);

  return 0;
}

/* Inherit from Socket class: Signal a termination of send */
int
QuicSocketBase::ShutdownSend (void)
{
  NS_LOG_FUNCTION (this);



  return 0;
}

/* Inherit from Socket class: Signal a termination of receive */
int
QuicSocketBase::ShutdownRecv (void)
{
  NS_LOG_FUNCTION (this);

  return 0;
}

void
QuicSocketBase::SetNode (Ptr<Node> node)
{
//NS_LOG_FUNCTION (this);

  m_node = node;
}

Ptr<Node>
QuicSocketBase::GetNode (void) const
{
//NS_LOG_FUNCTION_NOARGS ();

  return m_node;
}

/* Inherit from Socket class: Return local address:port */
int
QuicSocketBase::GetSockName (Address &address) const
{
  NS_LOG_FUNCTION (this);

  return m_quicl4->GetSockName (this, address);
}

int
QuicSocketBase::GetPeerName (Address &address) const
{
  NS_LOG_FUNCTION (this);

  return m_quicl4->GetPeerName (this, address);
}

/* Inherit from Socket class: Get the max number of bytes an app can send */
uint32_t
QuicSocketBase::GetTxAvailable (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t available = m_txBuffer->Available ();
  return available > m_pendingWriteBytes ? available - m_pendingWriteBytes : 0;
}

/* Inherit from Socket class: Get the max number of bytes an app can read */
uint32_t
QuicSocketBase::GetRxAvailable (void) const
{
  NS_LOG_FUNCTION (this);

  return m_rxBuffer->Available ();
}

/* Inherit from Socket class: Returns error code */
enum Socket::SocketErrno
QuicSocketBase::GetErrno (void) const
{
  return m_errno;
}

/* Inherit from Socket class: Returns socket type, NS3_SOCK_STREAM */
enum Socket::SocketType
QuicSocketBase::GetSocketType (void) const
{
  return NS3_SOCK_STREAM;
}

//////////////////////////////////////////////////////////////////////////////////////

/* Clean up after Bind. Set up callback functions in the end-point. */
int
QuicSocketBase::SetupCallback (void)
{
  NS_LOG_FUNCTION (this);

  if (m_quicl4 == nullptr)
    {
      return -1;
    }
  else
    {
      m_quicl4->SetRecvCallback (
        MakeCallback (&QuicSocketBase::ReceivedData, this), this);
    }

  return 0;
}

int
QuicSocketBase::AppendingRx (Ptr<Packet> frame, Address &address)
{

  NS_LOG_FUNCTION (this);

  // The stream layer already advanced its delivered offset and the packet carrying these bytes is
  // acknowledged: dropping them here would punch a hole into the stream for good, so they are kept even
  // when they do not fit the notional size of the buffer
  if (!m_rxBuffer->Add (frame, true))
    {
      NS_LOG_INFO ("Nothing to deliver (empty frame)");
      return 0;
    }
  else
    {
      NS_LOG_INFO ("Notify Data Recv");
      NotifyDataRecv ();   // trigger the application method
    }

  return frame->GetSize ();
}

void
QuicSocketBase::SetQuicL4 (Ptr<QuicL4Protocol> quic)
{
  NS_LOG_FUNCTION (this);

  m_quicl4 = quic;
}

void
QuicSocketBase::SetConnectionId (uint64_t connectionId)
{
  NS_LOG_FUNCTION_NOARGS ();

  m_connectionId = connectionId;
}

void
QuicSocketBase::InitializeScheduling ()
{
  ObjectFactory schedulerFactory;
  schedulerFactory.SetTypeId (m_schedulingTypeId);
  Ptr<QuicSocketTxScheduler> sched = schedulerFactory.Create<QuicSocketTxScheduler> ();
  m_txBuffer->SetScheduler (sched);
  for (const auto &kv : m_streamPriorities)
    {
      sched->SetStreamPriority (kv.first, kv.second);
    }
  SetDefaultLatency (m_defaultLatency);
}

uint64_t
QuicSocketBase::GetConnectionId (void) const
{
  NS_LOG_FUNCTION_NOARGS ();

  return m_connectionId;
}

void
QuicSocketBase::SetVersion (uint32_t version)
{
  NS_LOG_FUNCTION (this);

  m_vers = version;
  return;
}

//////////////////////////////////////////////////////////////////////////////////////

bool
QuicSocketBase::SetAllowBroadcast (bool allowBroadcast)
{
  NS_LOG_FUNCTION (this);

  return (!allowBroadcast);
}

bool
QuicSocketBase::GetAllowBroadcast (void) const
{
  return false;
}

Ptr<QuicL5Protocol>
QuicSocketBase::CreateStreamController ()
{
  NS_LOG_FUNCTION (this);

  Ptr<QuicL5Protocol> quicl5 = CreateObject<QuicL5Protocol> ();

  quicl5->SetSocket (this);
  quicl5->SetNode (m_node);
  quicl5->SetConnectionId (m_connectionId);

  return quicl5;
}

void
QuicSocketBase::SendInitialHandshake (uint8_t type,
                                      const QuicHeader &quicHeader,
                                      Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << m_vers);

  if (type == QuicHeader::VERSION_NEGOTIATION)
    {
      NS_LOG_INFO ("Create VERSION_NEGOTIATION");
      m_receivedTransportParameters = false;
      m_couldContainTransportParameters = true;

      std::vector<uint32_t> supportedVersions;
      supportedVersions.push_back (QUIC_VERSION);
      supportedVersions.push_back (QUIC_VERSION_DRAFT_10);
      supportedVersions.push_back (QUIC_VERSION_NS3_IMPL);
      supportedVersions.push_back (0x1a2a3a4a);   // RFC 9000 §15: reserved version (greasing)

      // the supported versions, four bytes each in network byte order (RFC 9000 s17.2.1)
      std::vector<uint8_t> buffer (4 * supportedVersions.size ());
      for (size_t i = 0; i < supportedVersions.size (); i++)
        {
          buffer[4 * i] = (supportedVersions[i] >> 24);
          buffer[4 * i + 1] = (supportedVersions[i] >> 16);
          buffer[4 * i + 2] = (supportedVersions[i] >> 8);
          buffer[4 * i + 3] = (supportedVersions[i]);
        }
      Ptr<Packet> payload = Create<Packet> (buffer.data (), buffer.size ());

      Ptr<Packet> p = Create<Packet> (buffer.data (), buffer.size ());
      QuicHeader head = QuicHeader::CreateVersionNegotiation (
        quicHeader.GetConnectionId (),
        QUIC_VERSION_NEGOTIATION,
        supportedVersions);

      // Set initial congestion window and Ssthresh
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
      m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

      m_quicl4->SendPacket (this, p, head);
      m_txTrace (p, head, this);
      NotifyDataSent (p->GetSize ());

    }
  else if (type == QuicHeader::INITIAL)
    {
      // Set initial congestion window and Ssthresh
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
      m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

      NS_LOG_INFO ("Create INITIAL");
      Ptr<Packet> p = Create<Packet> ();
      p->AddHeader (OnSendingTransportParameters ());
      // the RFC says that
      // "Clients MUST ensure that the first Initial packet they
      // send is sent in a UDP datagram that is at least 1200 octets."
      Ptr<Packet> payload = Create<Packet> (
        GetInitialPacketSize () - p->GetSize ());
      p->AddAtEnd (payload);

      m_quicl5->DispatchSend (p, QuicStream::HANDSHAKE_STREAM_ID);

    }
  else if (type == QuicHeader::RETRY)
    {
      NS_LOG_INFO ("Create RETRY");
      Ptr<Packet> p = Create<Packet> ();
      p->AddHeader (OnSendingTransportParameters ());
      Ptr<Packet> payload = Create<Packet> (
        GetInitialPacketSize () - p->GetSize ());
      p->AddAtEnd (payload);

      m_quicl5->DispatchSend (p, QuicStream::HANDSHAKE_STREAM_ID);
    }
  else if (type == QuicHeader::HANDSHAKE)
    {
      NS_LOG_INFO ("Create HANDSHAKE");
      Ptr<Packet> p = Create<Packet> ();
      if (m_socketState == CONNECTING_SVR)
        {
          p->AddHeader (OnSendingTransportParameters ());
          // Initial congestion window (the VERSION_NEGOTIATION path sets it otherwise)
          m_tcb->m_cWnd = m_tcb->m_initialCWnd;
          m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
        }

      Ptr<Packet> payload = Create<Packet> (
        GetInitialPacketSize () - p->GetSize ());
      p->AddAtEnd (payload);

      m_quicl5->DispatchSend (p, QuicStream::HANDSHAKE_STREAM_ID);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
    }
  else if (type == QuicHeader::ZRTT_PROTECTED)
    {
      NS_LOG_INFO ("Create ZRTT_PROTECTED");
      Ptr<Packet> p = Create<Packet> ();
      p->AddHeader (OnSendingTransportParameters ());

      m_quicl5->DispatchSend (p, QuicStream::HANDSHAKE_STREAM_ID);

    }
  else
    {

      NS_LOG_INFO ("Wrong Handshake Type");

      return;

    }
}

void
QuicSocketBase::OnReceivedFrame (QuicSubheader &sub)
{
  NS_LOG_FUNCTION (this << (uint64_t)sub.GetFrameType ());

  uint8_t frameType = sub.GetFrameType ();

  switch (frameType)
    {

      case QuicSubheader::ACK:
        NS_LOG_INFO ("Received ACK frame");
        OnReceivedAckFrame (sub);
        break;

      case QuicSubheader::CONNECTION_CLOSE:
        NS_LOG_INFO ("Received CONNECTION_CLOSE frame");
        if (m_socketState != CLOSING || m_closeOnEmpty)
          {
            EnterDraining ();
          }
        break;

      case QuicSubheader::CONNECTION_CLOSE_APP:
        NS_LOG_INFO ("Received CONNECTION_CLOSE_APP frame");
        if (m_socketState != CLOSING || m_closeOnEmpty)
          {
            EnterDraining ();
          }
        break;

      case QuicSubheader::PADDING:
        NS_LOG_INFO ("Received PADDING frame");
        // no need to do anything
        break;

      case QuicSubheader::MAX_DATA:
        // set the maximum amount of data that can be sent
        // on this connection
        NS_LOG_INFO ("Received MAX_DATA frame");
        SetConnectionMaxData (sub.GetMaxData ());
        break;

      case QuicSubheader::MAX_STREAMS_BIDI:
      case QuicSubheader::MAX_STREAMS_UNI:
        {
          // msquic QuicStreamSetUpdateMaxStreams: the limit only grows
          bool bidi = frameType == QuicSubheader::MAX_STREAMS_BIDI;
          if (sub.GetMaxStreamId () > (1ULL << 60))
            {
              // RFC 9000 s19.11: a limit above 2^60 cannot be expressed as a stream id
              AbortConnection (QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
                               "MAX_STREAMS above 2^60");
              return;
            }
          NS_LOG_INFO ("Received MAX_STREAMS frame, bidirectional " << bidi << " limit " << sub.GetMaxStreamId ());
          uint64_t &limit = m_peerMaxStreams[bidi ? 0 : 1];
          if (sub.GetMaxStreamId () > limit)
            {
              limit = sub.GetMaxStreamId ();
            }
          break;
        }

      case QuicSubheader::PING:
        // TODO
        NS_LOG_INFO ("Received PING frame");
        break;

      case QuicSubheader::DATA_BLOCKED:
        // RFC 9000 §19.12: peer is blocked by flow control — respond with MAX_DATA
        NS_LOG_INFO ("Received DATA_BLOCKED frame — sending MAX_DATA (RFC 9000 §19.12)");
        // (through the transmit buffer: a MAX_DATA that is lost must be sent again)
        SendControlFrame (QuicSubheader::CreateMaxData (m_quicl5->GetMaxData ()));
        break;

      case QuicSubheader::STREAMS_BLOCKED_BIDI:
      case QuicSubheader::STREAMS_BLOCKED_UNI:
        // msquic only logs "Peer Streams FC blocked": new credit comes from streams finishing
        if (sub.GetStreamId () > (1ULL << 60))
          {
            // RFC 9000 s19.14: a limit above 2^60 is a frame encoding error
            AbortConnection (QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
                             "STREAMS_BLOCKED above 2^60");
            return;
          }
        NS_LOG_INFO ("Received STREAMS_BLOCKED frame (limit " << sub.GetStreamId () << ")");
        break;

      case QuicSubheader::NEW_CONNECTION_ID:
        {
          // RFC 9000 s19.15, msquic connection.c
          if (sub.GetRetirePriorTo () > sub.GetSequence ())
            {
              AbortConnection (QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
                               "NEW_CONNECTION_ID retires ids it has not issued yet");
              return;
            }
          bool known = false;
          for (auto &cid : m_dstCids)
            {
              if (cid.sequence == sub.GetSequence ())
                {
                  known = true;
                  if (cid.id != sub.GetConnectionId ())
                    {
                      AbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                       "NEW_CONNECTION_ID reuses a sequence number");
                      return;
                    }
                }
            }
          if (!known)
            {
              QuicCidEntry cid;
              cid.sequence = sub.GetSequence ();
              cid.id = sub.GetConnectionId ();
              cid.tokenHi = sub.GetResetTokenHi ();
              cid.tokenLo = sub.GetResetTokenLo ();
              // an id below the retire-prior-to line is retired at once
              cid.retired = cid.sequence < m_peerRetirePriorTo;
              m_dstCids.push_back (cid);
              if (cid.retired)
                {
                  SendControlFrame (QuicSubheader::CreateRetireConnectionId (cid.sequence));
                }
            }
          if (sub.GetRetirePriorTo () > m_peerRetirePriorTo)
            {
              m_peerRetirePriorTo = sub.GetRetirePriorTo ();
              for (auto &cid : m_dstCids)
                {
                  if (cid.sequence < m_peerRetirePriorTo && !cid.retired)
                    {
                      RetireDestCid (cid);
                    }
                }
              for (auto &path : m_paths)
                {
                  for (auto &cid : m_dstCids)
                    {
                      if ((int64_t) cid.sequence == path.destCidSequence && cid.retired)
                        {
                          QuicCidEntry *fresh = UnusedDestCid ();
                          if (fresh != nullptr)
                            {
                              fresh->used = true;
                              path.destCidSequence = (int64_t) fresh->sequence;
                              if (path.active)
                                {
                                  m_destCid = fresh->id;
                                }
                            }
                        }
                    }
                }
            }
          if (GetActiveDestCids () > kActiveCidLimit)
            {
              AbortConnection (QuicSubheader::TransportErrorCodes_t::CONNECTION_ID_LIMIT_ERROR,
                               "More connection ids than the limit we announced");
              return;
            }
          NS_LOG_INFO ("Received NEW_CONNECTION_ID frame (sequence=" << sub.GetSequence () << ")");
          break;
        }

      case QuicSubheader::RETIRE_CONNECTION_ID:
        {
          // RFC 9000 s19.16: the peer stops using one of the ids we issued; msquic issues a replacement
          if (sub.GetSequence () >= m_nextSrcCidSequence)
            {
              AbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                               "RETIRE_CONNECTION_ID for an id that was not issued");
              return;
            }
          for (auto &cid : m_srcCids)
            {
              if (cid.sequence == sub.GetSequence () && !cid.retired)
                {
                  cid.retired = true;
                  if (cid.sequence != 0)
                    {
                      m_quicl4->UnregisterConnectionId (cid.id);
                    }
                  while (GetActiveSourceCids () < std::min<uint32_t> (m_peerActiveCidLimit, kActiveCidLimit))
                    {
                      IssueSourceCid ();
                    }
                  break;
                }
            }
          NS_LOG_INFO ("Received RETIRE_CONNECTION_ID frame (sequence=" << sub.GetSequence () << ")");
          break;
        }

      case QuicSubheader::NEW_TOKEN:
        // RFC 9000 §19.7: a server must treat a NEW_TOKEN as a connection error; a client may ignore it
        // (the simulation issues no tokens)
        if (m_isServerSide)
          {
            AbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                             "NEW_TOKEN received by a server");
            return;
          }
        NS_LOG_INFO ("Received NEW_TOKEN frame (ignored in simulation)");
        break;

      case QuicSubheader::IMMEDIATE_ACK:
        m_immediateAckRequested = true;
        break;

      case QuicSubheader::ACK_FREQUENCY:
        {
          // msquic connection.c: always accepted; older sequence numbers are ignored
          if (sub.GetAckFreqMaxDelayUs () < 1000)
            {
              AbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                               "ACK_FREQUENCY RequestedMaxAckDelay is less than the timer resolution");
              return;
            }
          if (sub.GetAckFreqSequence () < m_nextRecvAckFreqSeq)
            {
              break;
            }
          m_nextRecvAckFreqSeq = sub.GetAckFreqSequence () + 1;
          m_tcb->m_kDelayedAckTimeout = MicroSeconds (sub.GetAckFreqMaxDelayUs ());
          m_ackTolerance = (uint8_t) std::min<uint64_t> (sub.GetAckFreqThreshold (), 255);
          m_ackReorderingThreshold = (uint8_t) std::min<uint64_t> (sub.GetAckFreqReordering (), 255);
          NS_LOG_INFO ("Updating packet tolerance to " << (uint32_t) m_ackTolerance);
          break;
        }

      case QuicSubheader::HANDSHAKE_DONE:
        // RFC 9000 §19.20: client receives HANDSHAKE_DONE, handshake is confirmed
        NS_LOG_INFO ("Received HANDSHAKE_DONE frame — handshake confirmed (RFC 9000 §19.20)");
        if (m_isServerSide)
          {
            // RFC 9000 s19.20: a server must treat a HANDSHAKE_DONE as a connection error
            AbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                             "HANDSHAKE_DONE received by a server");
            return;
          }
        m_connected = true;
        break;

      case QuicSubheader::PATH_CHALLENGE:
        {
          // RFC 9000 s8.2.2: the response goes back on the path the challenge arrived on
          NS_LOG_INFO ("Received PATH_CHALLENGE frame, sending PATH_RESPONSE");
          if (!m_paths.empty ())
            {
              size_t index = (m_rxPathIndex >= 0 && m_rxPathIndex < (int) m_paths.size ()) ? (size_t) m_rxPathIndex : 0;
              SendPathResponse (m_paths[index], sub.GetData ());
            }
          break;
        }

      case QuicSubheader::PATH_RESPONSE:
        {
          NS_LOG_INFO ("Received PATH_RESPONSE frame");
          for (auto &path : m_paths)
            {
              if (!path.validated && path.validationStart.IsStrictlyPositive () && path.challenge == sub.GetData ())
                {
                  SetPathValid (path);
                  break;
                }
            }
          break;
        }

      default:
        // RFC 9000 §12.4: receiver MUST treat unknown frame types as FRAME_ENCODING_ERROR
        AbortConnection (
          QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
          "Received unknown frame type");
        return;
    }

}

Ptr<Packet>
QuicSocketBase::OnSendingAckFrame ()
{
  NS_LOG_FUNCTION (this);

  NS_ABORT_MSG_IF (m_receivedPacketNumbers.Empty (),
                   " Sending Ack Frame without packets to acknowledge");

//m_delAckEvent.Cancel();
//m_delAckCount = 0;

  NS_LOG_INFO ("Attach an ACK frame to the packet");

  // Walk the received ranges from the newest down: the first gives the largest acknowledged, every
  // older one becomes an additional block, up to m_maxTrackedGaps of them. The oldest range
  // reported ends at its first packet number (the ACK floor, carried in the first-block field):
  // it tells the sender how far down the acknowledgement reaches when older ranges are left out.
  const auto &ranges = m_receivedPacketNumbers.Ranges ();
  auto it = ranges.rbegin ();
  uint32_t largestAcknowledged = it->second;
  m_largestPnAckedByUs = std::max (m_largestPnAckedByUs, largestAcknowledged);
  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  uint32_t ackFloor = it->first;
  for (auto prev = it++; it != ranges.rend () && gaps.size () < m_maxTrackedGaps; prev = it++)
    {
      additionalAckBlocks.push_back (it->second);
      gaps.push_back (prev->first - 1);
      ackFloor = it->first;
    }

  // RFC 9000 s19.3: the ack delay is the time since the largest acknowledged packet arrived, in microseconds
  // divided by 2^ack_delay_exponent (our own exponent)
  Time delay = Simulator::Now () - m_largestRecvTime;
  uint64_t ack_delay = delay.GetMicroSeconds () >> m_ack_delay_exponent;
  QuicSubheader sub = QuicSubheader::CreateAck (
    largestAcknowledged, ack_delay, ackFloor,
    gaps, additionalAckBlocks);

  Ptr<Packet> ackFrame = Create<Packet> ();
  ackFrame->AddHeader (sub);

  return ackFrame;
}

void
QuicSocketBase::OnReceivedAckFrame (QuicSubheader &sub)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("Process ACK");

  // RFC 9000 s19.3: the sender divided the delay by 2^ack_delay_exponent (the peer's exponent);
  // from here on the ack delay is in microseconds
  sub.SetAckDelay (sub.GetAckDelay () << m_peerAckDelayExponent);

  // Generate RateSample
  struct RateSample * rs = m_txBuffer->GetRateSample ();
  rs->m_priorInFlight = m_tcb->m_bytesInFlight.Get ();

  m_tcb->m_ptoCountForLoss = m_tcb->m_rtoCount;

  uint32_t lostOut = m_txBuffer->GetLost ();
  uint32_t delivered = m_tcb->m_delivered;

  uint32_t previousWindow = m_txBuffer->BytesInFlight ();

  std::vector<uint32_t> additionalAckBlocks = sub.GetAdditionalAckBlocks ();
  std::vector<uint32_t> gaps = sub.GetGaps ();
  uint32_t largestAcknowledged = sub.GetLargestAcknowledged ();
  uint32_t ackFloor = (uint32_t) sub.GetFirstAckBlock ();
  m_txBuffer->SetAckFloor (ackFloor);
  m_tcb->m_lastAckedSeq = largestAcknowledged;
  uint32_t ackBlockCount = sub.GetAckBlockCount ();

  // RFC 9002 §2: update per-space largest-acked
  PacketNumberSpace space = m_currentRecvPacketNumberSpace;
  if (SequenceNumber32 (largestAcknowledged) > m_tcb->m_largestAckedPacketSpace[space])
    {
      m_tcb->m_largestAckedPacketSpace[space] = SequenceNumber32 (largestAcknowledged);
    }

  NS_ABORT_MSG_IF (
    ackBlockCount != additionalAckBlocks.size ()
    and ackBlockCount != gaps.size (),
    "Received Corrupted Ack Frame.");

  std::vector<Ptr<QuicSocketTxItem> > ackedPackets = m_txBuffer->OnAckUpdate (
    m_tcb, largestAcknowledged, additionalAckBlocks, gaps);

  CheckSpuriousLosses (largestAcknowledged, additionalAckBlocks, gaps, ackFloor);

  if (m_pmtudProbePn != 0)
    {
      std::vector<uint32_t> ups = additionalAckBlocks;
      ups.insert (ups.begin (), largestAcknowledged);
      bool covered = false;
      for (size_t i = 0; i < ups.size () && !covered; ++i)
        {
          bool aboveGap = (i >= gaps.size ()) ? (m_pmtudProbePn >= ackFloor) : (m_pmtudProbePn > gaps[i]);
          covered = (m_pmtudProbePn <= ups[i]) && aboveGap;
        }
      if (covered)
        {
          OnMtuProbeAcked ();
        }
    }

  // Count newly acked bytes
  uint32_t ackedBytes = previousWindow - m_txBuffer->BytesInFlight ();

  m_txBuffer->GenerateRateSample ();
  rs->m_packetLoss = std::abs ((int) lostOut - (int) m_txBuffer->GetLost ());
  m_tcb->m_lastAckedSackedBytes = m_tcb->m_delivered - delivered;

  // RTO packet acknowledged - IETF Draft QUIC Recovery, Sec. 4.3.3
  if (m_tcb->m_rtoCount > 0)
    {
      // Packets after the RTO have been acknowledged
      if (m_tcb->m_largestSentBeforeRto.GetValue () < largestAcknowledged)
        {

          // Number of NEW packets (by packet number) acknowledged after the RTO.
          // largestAcknowledged and largestSentBeforeRto are PACKET NUMBERS, not byte offsets.
          uint32_t newPackets = largestAcknowledged
                                - m_tcb->m_largestSentBeforeRto.GetValue ();
          uint32_t inFlightBeforeRto = m_txBuffer->BytesInFlight ();
          m_txBuffer->ResetSentList (newPackets);
          std::vector<Ptr<QuicSocketTxItem> > lostPackets =
            m_txBuffer->DetectLostPackets ();
          if (m_quicCongestionControlLegacy && !lostPackets.empty ())
            {
              // Reset congestion window and go into loss mode
              m_tcb->m_cWnd = m_tcb->m_kMinimumWindow;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                m_tcb, inFlightBeforeRto);
              m_tcb->m_congState = TcpSocketState::CA_LOSS;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_LOSS);
            }
        }
      // RFC 9002 s6.2.1: reset the PTO backoff when an ACK acknowledges new data
      if (!ackedPackets.empty ())
        {
          m_tcb->m_rtoCount = 0;
        }
    }

  // Tail loss probe packet acknowledged - IETF Draft QUIC Recovery, Sec. 4.3.2
  if (m_tcb->m_tlpCount > 0 && !ackedPackets.empty ())
    {
      m_tcb->m_tlpCount = 0;
    }

  // Find lost packets
  std::vector<Ptr<QuicSocketTxItem> > lostPackets =
    m_txBuffer->DetectLostPackets ();
  // Recover from losses
  if (!lostPackets.empty ())
    {
      if (m_quicCongestionControlLegacy)
        {
          //Enter recovery (RFC 6675, Sec. 5)
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY)
            {
              m_tcb->m_congState = TcpSocketState::CA_RECOVERY;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_RECOVERY);
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                m_tcb, BytesInFlight ());
              m_tcb->m_cWnd = m_tcb->m_ssThresh;
            }
          NS_ASSERT (m_tcb->m_congState == TcpSocketState::CA_RECOVERY);
        }
      else
        {
          UpdateLostSpanState (lostPackets);
          DynamicCast<QuicCongestionOps> (m_congestionControl)->OnPacketsLost (
            m_tcb, lostPackets);
        }
      DoRetransmit (lostPackets);
      if (m_tcb->m_ptoCountForLoss > 2)
        {
          // msquic: on persistent congestion the peer goes back to the default tolerance
          UpdatePeerAckTolerance (2);
        }
    }
  /* else */ if (ackedBytes > 0)
    {
      if (!m_quicCongestionControlLegacy)
        {
          NS_LOG_INFO ("Update the variables in the congestion control (QUIC)");
          // Process the ACK
          DynamicCast<QuicCongestionOps> (m_congestionControl)->OnAckReceived (
            m_tcb, sub, ackedPackets, rs);
          m_lastRtt = m_tcb->m_lastRtt;
        }
      else
        {
          uint32_t ackedSegments = ackedBytes / GetSegSize ();

          NS_LOG_INFO ("Update the variables in the congestion control (legacy), ackedBytes "
                       << ackedBytes << " ackedSegments " << ackedSegments);
          // new acks are ordered from the highest packet number to the smalles
          Ptr<QuicSocketTxItem> lastAcked = ackedPackets.at (0);

          NS_LOG_LOGIC ("Updating RTT estimate");
          // If the largest acked is newly acked, update the RTT.
          if (lastAcked->m_packetNumber >= m_tcb->m_largestAckedPacket)
            {
              Time ackDelay = MicroSeconds (sub.GetAckDelay ());
              m_tcb->m_lastRtt = Now () - lastAcked->m_lastSent - ackDelay;
              m_lastRtt = m_tcb->m_lastRtt;
            }
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY
              && m_tcb->m_congState != TcpSocketState::CA_LOSS)
            {
              // Increase the congestion window
              m_congestionControl->PktsAcked (m_tcb, ackedSegments,
                                              m_tcb->m_lastRtt);
              m_congestionControl->IncreaseWindow (m_tcb, ackedSegments);
            }
          else
            {
              if (m_tcb->m_endOfRecovery.GetValue () > largestAcknowledged)
                {
                  m_congestionControl->PktsAcked (m_tcb, ackedSegments,
                                                  m_tcb->m_lastRtt);
                  m_congestionControl->IncreaseWindow (m_tcb, ackedSegments);
                }
              else
                {
                  m_tcb->m_congState = TcpSocketState::CA_OPEN;
                  m_congestionControl->PktsAcked (m_tcb, ackedSegments, m_tcb->m_lastRtt);
                  m_congestionControl->CongestionStateSet (m_tcb, TcpSocketState::CA_OPEN);
                }
            }
        }
    }
  else
    {
      NS_LOG_INFO ("Received an ACK to ack an ACK");
    }

  // RFC 9002 §9.2: React to ECN-CE count increase in ACK_ECN frames.
  // In the simulator ECN marking is not produced by the IP layer, so this path
  // will not fire in normal simulations.  The logic is present for conformance.
  if (sub.GetFrameType () == QuicSubheader::ACK_ECN)
    {
      uint64_t newCeCount = sub.GetEcnCeCount ();
      if (newCeCount > m_tcb->m_peerEcnCeCount)
        {
          m_tcb->m_peerEcnCeCount = newCeCount;
          NS_LOG_INFO ("ECN-CE increment detected — entering congestion recovery (RFC 9002 §9.2)");
          Ptr<QuicCongestionOps> cc = DynamicCast<QuicCongestionOps> (m_congestionControl);
          if (!cc->InRecovery (m_tcb, m_tcb->m_largestAckedPacket))
            {
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_tcb->m_cWnd = std::max (
                (uint32_t)(m_tcb->m_cWnd * m_tcb->m_kLossReductionFactor),
                m_tcb->m_kMinimumWindow);
              m_tcb->m_ssThresh = m_tcb->m_cWnd;
            }
        }
    }

  // notify the application that more data can be sent
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }

  // try to send more data
  SendPendingData (m_connected);

  // Compute timers
  SetReTxTimeout ();
}

QuicTransportParameters
QuicSocketBase::OnSendingTransportParameters ()
{
  NS_LOG_FUNCTION (this);

  QuicTransportParameters transportParameters;
  transportParameters = transportParameters.CreateTransportParameters (
    m_initial_max_stream_data, m_max_data, m_initial_max_stream_id_bidi,
    (uint32_t) m_idleTimeout.Get ().GetMilliSeconds (),
    (uint8_t) m_omit_connection_id, (m_pmtudMaxSeg ? m_pmtudMaxSeg : m_tcb->m_segmentSize),
    m_ack_delay_exponent, m_initial_max_stream_id_uni);

  // RFC 9000 §18.2, 0x06/0x07: per-direction stream data limits
  transportParameters.SetInitialMaxStreamDataBidiRemote (m_initial_max_stream_data);
  transportParameters.SetInitialMaxStreamDataUni (m_initial_max_stream_data);
  // RFC 9000 §18.2, 0x0b: advertise our max_ack_delay (convert from ns-3 Time to ms)
  // (what we advertise is the longest we hold an ACK back: the delayed-ACK timer, not the peer's value)
  transportParameters.SetMaxAckDelay (static_cast<uint16_t> (
    std::min<int64_t> (m_tcb->m_kDelayedAckTimeout.GetMilliSeconds (), (1 << 14) - 1)));
  // msquic always advertises min_ack_delay (its timer resolution, 1 ms) and accepts ACK_FREQUENCY
  transportParameters.SetMinAckDelay (1000);
  transportParameters.SetActiveConnectionIdLimit (kActiveCidLimit);
  transportParameters.SetDisableActiveMigration (m_disableActiveMigration ? 1 : 0);

  // RFC 9000 §18.2: server generates a stateless reset token derived from connection ID
  // (pseudo-random, deterministic per connection)
  if (m_socketState == CONNECTING_SVR)
    {
      uint64_t tokenHi = 0;
      uint64_t tokenLo = 0;
      m_quicl4->GenerateStatelessResetToken (m_connectionId, tokenHi, tokenLo);
      transportParameters.SetStatelessResetToken (tokenHi, tokenLo);
      // RFC 9000 §18.2: server sets original_destination_connection_id = client's DCID
      transportParameters.SetOriginalDestinationConnectionId (m_connectionId);
    }
  // RFC 9000 §18.2: both endpoints set initial_source_connection_id = their own CID
  transportParameters.SetInitialSourceConnectionId (m_connectionId);

  return transportParameters;
}

void
QuicSocketBase::OnReceivedTransportParameters (
  QuicTransportParameters transportParameters)
{
  NS_LOG_FUNCTION (this);

  if (m_receivedTransportParameters)
    {
      NS_LOG_WARN ("Ignoring duplicate transport parameters (already received)");
      return;
    }
  m_receivedTransportParameters = true;

  // RFC 9000 §18.2: a client MUST NOT include a stateless reset token
  if (m_socketState == CONNECTING_SVR
      && (transportParameters.GetStatelessResetTokenHi () != 0 || transportParameters.GetStatelessResetTokenLo () != 0))
    {
      AbortConnection (QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
                       "A client must not send a stateless reset token");
      return;
    }
  if (transportParameters.GetStatelessResetTokenHi () != 0 || transportParameters.GetStatelessResetTokenLo () != 0)
    {
      m_hasPeerResetToken = true;
      m_peerResetTokenHi = transportParameters.GetStatelessResetTokenHi ();
      m_peerResetTokenLo = transportParameters.GetStatelessResetTokenLo ();
    }

  // The stream-id parameters are limits, not ids: their low bits carry no role information,
  // so the former role checks (which silently skipped all parameters) were removed.

  if (transportParameters.GetMaxPacketSize ()
      < QuicSocketBase::MIN_INITIAL_PACKET_SIZE
      or transportParameters.GetMaxPacketSize () > 65527)
    {
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
        "Invalid Max Packet Size value provided");
      return;
    }

  // RFC 9000 s18.2: out-of-range values are a TRANSPORT_PARAMETER_ERROR
  if (transportParameters.GetAckDelayExponent () > 20)
    {
      AbortConnection (QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
                       "ack_delay_exponent above 20");
      return;
    }
  if (transportParameters.GetMaxAckDelay () >= (1u << 14))
    {
      AbortConnection (QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
                       "max_ack_delay of 2^14 ms or more");
      return;
    }
  if (transportParameters.GetActiveConnectionIdLimit () < 2)
    {
      AbortConnection (QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
                       "active_connection_id_limit below 2");
      return;
    }

// version 15 has removed the upper bound on the idle timeout
// if (transportParameters.GetIdleTimeout () > 600)
//   {
//     AbortConnection (
//         QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
//         "Invalid Idle Timeout value provided");
//     return;
//   }

  NS_LOG_DEBUG (
    "Before applying received transport parameters " << " m_initial_max_stream_data " << m_initial_max_stream_data << " m_max_data " << m_max_data << " m_initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << " m_idleTimeout " << m_idleTimeout << " m_omit_connection_id " << m_omit_connection_id << " m_tcb->m_segmentSize " << m_tcb->m_segmentSize << " m_ack_delay_exponent " << m_ack_delay_exponent << " m_initial_max_stream_id_uni " << m_initial_max_stream_id_uni);

  // Peer limits for what we send; our own receive windows are left untouched
  m_peerInitialMaxStreamData = transportParameters.GetInitialMaxStreamData ();
  m_peerStreamData[0] = transportParameters.GetInitialMaxStreamData ();           // bidi, opened by the peer
  m_peerStreamData[1] = transportParameters.GetInitialMaxStreamDataBidiRemote ();  // bidi, opened by us
  m_peerStreamData[2] = transportParameters.GetInitialMaxStreamDataUni ();         // uni, opened by us
  m_peerMaxStreams[0] = transportParameters.GetInitialMaxStreamIdBidi ();
  m_peerMaxStreams[1] = transportParameters.GetInitialMaxStreamIdUni ();
  m_quicl5->UpdateInitialMaxStreamData ();
  SetConnectionMaxData (transportParameters.GetInitialMaxData ());

  // RFC 9000 s10.1: the effective idle timeout is the smaller of the two advertised values, a value of 0
  // meaning "no limit" for that endpoint (both 0: the timer is off)
  {
    Time peerIdle = MilliSeconds (transportParameters.GetIdleTimeout ());
    Time ownIdle = m_idleTimeout.Get ();
    if (ownIdle.IsZero ())
      {
        m_idleTimeout = peerIdle;
      }
    else if (!peerIdle.IsZero ())
      {
        m_idleTimeout = std::min (ownIdle, peerIdle);
      }
  }

  m_omit_connection_id = std::min (transportParameters.GetOmitConnection (),
                                   (uint8_t) m_omit_connection_id);

  {
    uint32_t cfgMax = m_pmtudMaxSeg ? m_pmtudMaxSeg : m_tcb->m_segmentSize;
    cfgMax = std::min ((uint32_t) transportParameters.GetMaxPacketSize (), cfgMax);
    uint32_t newSeg = cfgMax;
    if (m_pmtudEnabled && cfgMax + kPmtudOverhead > kPmtudInitialMtu)
      {
        // msquic starts every path at its minimum MTU and discovers the rest
        m_pmtudMaxSeg = cfgMax;
        newSeg = m_pmtudStarted ? m_tcb->m_segmentSize : kPmtudInitialMtu - kPmtudOverhead;
        if (!m_pmtudStarted)
          {
            m_pmtudStarted = true;
            m_pmtudSearchDone = false;
          }
      }
    if (newSeg != m_tcb->m_segmentSize)
      {
        uint32_t oldInitial = m_tcb->m_initialCWnd;
        m_tcb->m_segmentSize = newSeg;
        m_tcb->m_kMinimumWindow = 2 * newSeg;
        // RFC 9002 s7.2 / msquic: 10 datagrams
        m_tcb->m_initialCWnd = std::min (10 * newSeg, std::max ((uint32_t) 14720, 2 * newSeg));
        if (m_tcb->m_cWnd.Get () == oldInitial)
          {
            m_tcb->m_cWnd = m_tcb->m_initialCWnd;
          }
      }
  }

//m_stateless_reset_token = std::min(transportParameters.getStatelessResetToken(), m_stateless_reset_token);
  // RFC 9000 s18.2: the peer's ack_delay_exponent decodes the ACK frames it sends; ours encodes ours
  m_peerAckDelayExponent = transportParameters.GetAckDelayExponent ();

  // RFC 9000 §18.2, 0x0b: max_ack_delay — update TCB with peer's announced value (0 is valid: no delay)
  m_tcb->m_maxAckDelay = MilliSeconds (transportParameters.GetMaxAckDelay ());
  m_peerSupportsAckFreq = transportParameters.GetMinAckDelay () > 0;
  m_peerActiveCidLimit = transportParameters.GetActiveConnectionIdLimit ();
  m_peerDisablesMigration = transportParameters.GetDisableActiveMigration () != 0;

  NS_LOG_DEBUG (
    "After applying received transport parameters " << " m_initial_max_stream_data " << m_initial_max_stream_data << " m_max_data " << m_max_data << " m_initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << " m_idleTimeout " << m_idleTimeout << " m_omit_connection_id " << m_omit_connection_id << " m_tcb->m_segmentSize " << m_tcb->m_segmentSize << " m_ack_delay_exponent " << m_ack_delay_exponent << " m_initial_max_stream_id_uni " << m_initial_max_stream_id_uni);
}

int
QuicSocketBase::DoConnect (void)
{
  NS_LOG_FUNCTION (this);

  if (m_socketState != IDLE and m_socketState != QuicSocket::LISTENING)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  if (m_socketState == LISTENING)
    {
      SetState (CONNECTING_SVR);
    }
  else if (m_socketState == IDLE)
    {
      SetState (CONNECTING_CLT);
      QuicHeader q;
      SendInitialHandshake (QuicHeader::INITIAL, q, 0);
    }
  return 0;
}

int
QuicSocketBase::DoFastConnect (void)
{
  NS_LOG_FUNCTION (this);
  if (!IsVersionSupported (m_vers))
    {
      NS_LOG_WARN ("0RTT: m_vers=" << m_vers << " invalido apos reconexao; "
                   << "resetando para QUIC_VERSION_NS3_IMPL e prosseguindo com 0-RTT");
      m_vers = QUIC_VERSION_NS3_IMPL;
    }

  if (m_socketState != IDLE)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  else if (m_socketState == IDLE)
    {
      SetState (OPEN);
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      QuicHeader q;
      SendInitialHandshake (QuicHeader::ZRTT_PROTECTED, q, 0);
    }
  return 0;
}

void
QuicSocketBase::ConnectionSucceeded ()
{ // Wrapper to protected function NotifyConnectionSucceeded() so that it can
  // be called as a scheduled event
  NotifyConnectionSucceeded ();
  // The if-block below was moved from ProcessSynSent() to here because we need
  // to invoke the NotifySend() only after NotifyConnectionSucceeded() to
  // reflect the behaviour in the real world.
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }
}

void
QuicSocketBase::NotifyNewConnection (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);
  NotifyNewConnectionCreated (socket, from);
}

int
QuicSocketBase::DoClose (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO (this << " DoClose at time " << Simulator::Now ().GetSeconds ());

  if (m_socketState != IDLE)
    {
      SetState (IDLE);
      if (!m_closeNotified)
        {
          m_closeNotified = true;
          NotifyNormalClose ();
        }
    }

  SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
  return m_quicl4->RemoveSocket (this);
}

void
QuicSocketBase::ReceivedData (Ptr<Packet> p, const QuicHeader& quicHeader,
                              Address &address)
{
  NS_LOG_FUNCTION (this);

  m_rxTrace (p, quicHeader, this);

  NS_LOG_INFO ("Received packet of size " << p->GetSize ());

  // check if this packet is not received during the draining period
  if (!m_drainingPeriodEvent.IsPending ())
    {
      ArmIdleTimer ();   // reset the IDLE timeout
    }
  else   // If the socket is in Draining Period, discard the packets
    {
      return;
    }

  int onlyAckFrames = 0;
  bool unsupportedVersion = false;

  if (quicHeader.IsORTT () and m_socketState == LISTENING)
    {

      if (m_serverBusy)
        {
          AbortConnection (QuicSubheader::TransportErrorCodes_t::CONNECTION_REFUSED,
                           "Server too busy to accept new connections");
          return;
        }

      m_couldContainTransportParameters = true;

      m_currentRecvPacketNumberSpace = GetPacketNumberSpace (quicHeader);
      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      NotePacketReceived (quicHeader.GetPacketNumber ().GetValue ());

      m_connected = true;
      m_tcb->m_handshakeConfirmed = true;  // RFC 9002 §5.3: handshake confirmed (0-RTT server)
      DiscardInitialPacketSpace ();         // RFC 9002 §9.1: 0-RTT skips full handshake
      DiscardHandshakePacketSpace ();       // RFC 9002 §9.1: 0-RTT — no Handshake phase
      m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
        QuicHeader::PHASE_ZERO :
        m_keyPhase =
          QuicHeader::PHASE_ONE;
      SetState (OPEN);
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_couldContainTransportParameters = false;

    }
  else if (quicHeader.IsInitial () and m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Server receives INITIAL");
      if (m_serverBusy)
        {
          AbortConnection (QuicSubheader::TransportErrorCodes_t::CONNECTION_REFUSED,
                           "Server too busy to accept new connections");
          return;
        }

      if (p->GetSize () < QuicSocketBase::MIN_INITIAL_PACKET_SIZE)
        {
          std::stringstream error;
          error << "Initial Packet smaller than "
                << QuicSocketBase::MIN_INITIAL_PACKET_SIZE << " octects";
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
            error.str ().c_str ());
          return;
        }

      // RFC 9000 §8: track bytes received for anti-amplification
      m_bytesReceivedPreValidation += p->GetSize ();

      // The client Initial carries its transport parameters (stream 0)
      m_receivedTransportParameters = false;
      m_couldContainTransportParameters = true;
      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      NotePacketReceived (quicHeader.GetPacketNumber ().GetValue ());

      if (IsVersionSupported (quicHeader.GetVersion ()))
        {
          m_couldContainTransportParameters = false;
          SendInitialHandshake (QuicHeader::HANDSHAKE, quicHeader, p);
        }
      else
        {
          NS_LOG_INFO (this << " WRONG VERSION " << quicHeader.GetVersion ());
          unsupportedVersion = true;
          SendInitialHandshake (QuicHeader::VERSION_NEGOTIATION, quicHeader,
                                p);
        }
      return;
    }
  else if (quicHeader.IsHandshake () and m_socketState == CONNECTING_CLT)   // Undefined compiler behaviour if i try to receive transport parameters
    {
      NS_LOG_INFO ("Client receives HANDSHAKE");

      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      NotePacketReceived (quicHeader.GetPacketNumber ().GetValue ());

      m_tcb->m_handshakeConfirmed = true;  // RFC 9002 §5.3: handshake confirmed (client)
      DiscardInitialPacketSpace ();         // RFC 9002 §9.1: discard Initial on first Handshake recv
      SetState (OPEN);
      DiscardHandshakePacketSpace ();       // RFC 9002 §9.1: discard Handshake on reaching OPEN
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_couldContainTransportParameters = false;

      SendInitialHandshake (QuicHeader::HANDSHAKE, quicHeader, p);
      return;
    }
  else if (quicHeader.IsHandshake () and m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Server receives HANDSHAKE");

      // RFC 9000 §8: client address is validated once handshake completes
      m_peerAddressValidated = true;

      m_currentRecvPacketNumberSpace = GetPacketNumberSpace (quicHeader);
      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      NotePacketReceived (quicHeader.GetPacketNumber ().GetValue ());

      m_tcb->m_handshakeConfirmed = true;  // RFC 9002 §5.3: handshake confirmed (server)
      DiscardInitialPacketSpace ();         // RFC 9002 §9.1: discard Initial on Handshake recv
      SetState (OPEN);
      DiscardHandshakePacketSpace ();       // RFC 9002 §9.1: discard Handshake on reaching OPEN
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      // RFC 9000 s19.20: the server sends HANDSHAKE_DONE; like every frame but ACK and PADDING it is
      // retransmitted if its packet is lost (RFC 9000 s13.3), so it goes through the transmit buffer
      SendControlFrame (QuicSubheader::CreateHandshakeDone ());
      NS_LOG_INFO ("Server queued HANDSHAKE_DONE (RFC 9000 s19.20)");
      SendPendingData (true);
      return;
    }
  else if (quicHeader.IsVersionNegotiation ()
           and m_socketState == CONNECTING_CLT)
    {
      NS_LOG_INFO ("Client receives VERSION_NEGOTIATION");

      std::vector<uint8_t> buffer (p->GetSize ());
      p->CopyData (buffer.data (), buffer.size ());

      // RFC 9000 s17.2.1: the supported versions, four bytes each in network byte order
      std::vector<uint32_t> receivedVersions;
      for (size_t i = 0; i + 4 <= buffer.size (); i = i + 4)
        {
          receivedVersions.push_back (((uint32_t) buffer[i] << 24) | ((uint32_t) buffer[i + 1] << 16)
                                      | ((uint32_t) buffer[i + 2] << 8) | (uint32_t) buffer[i + 3]);
        }

      // RFC 9000 s6.2: a client discards a Version Negotiation packet that lists the version it chose
      // (it would be a forged or looping packet)
      if (std::find (receivedVersions.begin (), receivedVersions.end (), m_vers) != receivedVersions.end ())
        {
          NS_LOG_INFO ("Ignoring a Version Negotiation packet that lists the version in use");
          return;
        }

      std::vector<uint32_t> supportedVersions;
      supportedVersions.push_back (QUIC_VERSION);
      supportedVersions.push_back (QUIC_VERSION_DRAFT_10);
      supportedVersions.push_back (QUIC_VERSION_NS3_IMPL);

      uint32_t foundVersion = 0;
      for (size_t i = 0; i < receivedVersions.size (); i++)
        {
          for (size_t j = 0; j < supportedVersions.size (); j++)
            {
//			NS_LOG_INFO("rec " << receivedVersions[i] << " myvers " << m_supportedVersions[j] );
              if (receivedVersions[i] == supportedVersions[j])
                {
                  foundVersion = receivedVersions[i];
                }
            }
        }

      if (foundVersion != 0)
        {
          NS_LOG_INFO ("A matching supported version is found " << foundVersion << " re-send initial");
          m_vers = foundVersion;
          SendInitialHandshake (QuicHeader::INITIAL, quicHeader, p);
        }
      else
        {
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::CONNECTION_ID_LIMIT_ERROR,
            "No supported Version found by the Client");
          return;
        }
      return;
    }
  else if (quicHeader.IsShort () and (m_socketState == OPEN or IsFlushingOnClose ()))
    {
      // RFC 9000 §12.3: duplicate packet numbers MUST be discarded
      SequenceNumber32 pktNum = quicHeader.GetPacketNumber ();
      bool isDuplicate = m_receivedPacketNumbers.Contains (pktNum.GetValue ());
      if (isDuplicate)
        {
          NS_LOG_INFO ("Duplicate packet number " << pktNum << " discarded (RFC 9000 §12.3)");
          return;
        }

      // RFC 9000 s17.4: the spin value follows the highest-numbered packet received so far; the server
      // reflects it, the client sends the opposite, so the bit flips once per round trip
      bool newLargest = m_receivedPacketNumbers.Empty () || pktNum.GetValue () > m_receivedPacketNumbers.Largest ();
      NotePacketReceived (pktNum.GetValue ());
      if (newLargest)
        {
          m_spinBit = m_isServerSide ? quicHeader.GetSpinBit () : !quicHeader.GetSpinBit ();
        }
      m_currentRecvPacketNumberSpace = GetPacketNumberSpace (quicHeader);
      onlyAckFrames = m_quicl5->DispatchRecv (p, address);

    }
  else if (m_socketState == CLOSING)
    {
      // RFC 9000 §10.2: during closing/draining, silently discard received packets.
      // An endpoint MUST NOT send further frames after entering the draining state.
      NS_LOG_INFO ("Discarding packet received in CLOSING/draining state (RFC 9000 §10.2)");
      return;
    }
  else
    {

      return;
    }

  // trigger the process for ACK handling if the received packet was not ACK only
  NS_LOG_DEBUG ("onlyAckFrames " << onlyAckFrames << " unsupportedVersion " << unsupportedVersion);
  if (onlyAckFrames == 1 && !unsupportedVersion)
    {
      m_lastReceived = Simulator::Now ();
      NS_LOG_DEBUG ("Call MaybeQueueAck");
      MaybeQueueAck ();
    }

  if (quicHeader.IsShort () && !unsupportedVersion)
    {
      RecvPostProcessing ();
    }
}

uint32_t
QuicSocketBase::GetInitialMaxStreamData () const
{
  return m_peerInitialMaxStreamData;
}

bool
QuicSocketBase::IsFlushingOnClose () const
{
  return m_closeOnEmpty && m_socketState == CLOSING;
}

uint32_t
QuicSocketBase::GetOwnInitialMaxStreamData () const
{
  return m_initial_max_stream_data;
}

uint32_t
QuicSocketBase::GetConnRecvWindow () const
{
  return m_max_data;
}

Time
QuicSocketBase::GetSmoothedRtt () const
{
  return m_tcb->m_smoothedRtt;
}

uint64_t
QuicSocketBase::GetConnectionMaxData () const
{
  return m_peerMaxData;
}

void
QuicSocketBase::SetConnectionMaxData (uint64_t maxData)
{
  if (maxData > m_peerMaxData)
    {
      m_peerMaxData = maxData;
      m_quicl5->OnConnectionWindowUpdate ();
    }
}

QuicSocket::QuicStates_t
QuicSocketBase::GetSocketState () const
{
  return m_socketState;
}

void
QuicSocketBase::SetState (TracedValue<QuicStates_t> newstate)
{
  NS_LOG_FUNCTION (this);

  if (m_quicl4->IsServer ())
    {
      NS_LOG_INFO (
        "Server " << QuicStateName[m_socketState] << " -> " << QuicStateName[newstate] << "");
    }
  else
    {
      NS_LOG_INFO (
        "Client " << QuicStateName[m_socketState] << " -> " << QuicStateName[newstate] << "");
    }

  m_socketState = newstate;
  if (newstate == OPEN && m_quicl5 != nullptr)
    {
      // Application data was held back during the handshake
      m_quicl5->OnConnectionWindowUpdate ();
    }
  if (newstate == OPEN && m_paths.empty ())
    {
      InitPaths ();
      IssueSourceCids ();
    }
  if (newstate == OPEN && m_pmtudEnabled && !m_pmtudSearchDone && m_pmtudMaxSeg > m_tcb->m_segmentSize)
    {
      Simulator::ScheduleNow (&QuicSocketBase::StartMtuDiscovery, this);
    }
  if (newstate == OPEN && !m_pendingWrites.empty ())
    {
      auto writes = std::move (m_pendingWrites);
      m_pendingWrites.clear ();
      m_pendingWriteBytes = 0;
      for (auto &w : writes)
        {
          m_quicl5->DispatchSend (w.first, w.second);
        }
    }
  if (newstate == OPEN && m_closeAfterHandshake)
    {
      m_closeAfterHandshake = false;
      Simulator::ScheduleNow (&QuicSocketBase::Close, this);
    }
}

bool
QuicSocketBase::IsVersionSupported (uint32_t version)
{
  if (version == QUIC_VERSION || version == QUIC_VERSION_DRAFT_10
      || version == QUIC_VERSION_NS3_IMPL)
    {
      return true;
    }
  else
    {
      return false;
    }
}

void
QuicSocketBase::AbortConnection (uint16_t transportErrorCode,
                                 const char* reasonPhrase,
                                 bool applicationClose)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO (
    "Abort connection " << transportErrorCode << " because " << reasonPhrase);

  m_transportErrorCode = transportErrorCode;

  QuicSubheader quicSubheader;
  Ptr<Packet> frame = Create<Packet> ();
  if (!applicationClose)
    {
      quicSubheader = QuicSubheader::CreateConnectionClose (
        m_transportErrorCode, reasonPhrase);
    }
  else
    {
      quicSubheader = QuicSubheader::CreateApplicationClose (
        m_transportErrorCode, reasonPhrase);
    }
  frame->AddHeader (quicSubheader);

  QuicHeader quicHeader;
  switch (m_socketState)
    {
      case CONNECTING_CLT:
        quicHeader = QuicHeader::CreateInitial (m_connectionId, m_vers,
                                                m_tcb->m_nextTxSequence++);
        break;
      case CONNECTING_SVR:
        quicHeader = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                                  m_tcb->m_nextTxSequence++);
        break;
      case OPEN:
        quicHeader =
          !m_connected ?
          QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                       m_tcb->m_nextTxSequence++) :
          QuicHeader::CreateShort (GetDestCid (),
                                   m_tcb->m_nextTxSequence++,
                                   !m_omit_connection_id, m_keyPhase, m_spinBit);
        break;
      case CLOSING:
        quicHeader = QuicHeader::CreateShort (GetDestCid (),
                                              m_tcb->m_nextTxSequence++,
                                              !m_omit_connection_id,
                                              m_keyPhase, m_spinBit);
        break;
      default:
        NS_ABORT_MSG (
          "AbortConnection in unfeasible Socket State for the request");
        return;
    }
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddAtEnd (frame);
  uint32_t sz = packet->GetSize ();

  m_quicl4->SendPacket (this, packet, quicHeader);
  m_txTrace (packet, quicHeader, this);
  NotifyDataSent (sz);

  Close ();
}

bool
QuicSocketBase::GetReceivedTransportParametersFlag () const
{
  return m_receivedTransportParameters;
}

bool
QuicSocketBase::CheckIfPacketOverflowMaxDataLimit (
  std::vector<std::pair<Ptr<Packet>, QuicSubheader> > disgregated)
{
  NS_LOG_FUNCTION (this);
  uint32_t validPacketSize = 0;

  for (auto frame_recv_it = disgregated.begin ();
       frame_recv_it != disgregated.end () and !disgregated.empty ();
       ++frame_recv_it)
    {
      QuicSubheader sub = (*frame_recv_it).second;
      // (*frame_recv_it)->PeekHeader (sub);

      if (sub.IsStream () and sub.GetStreamId () != QuicStream::HANDSHAKE_STREAM_ID)
        {
          validPacketSize += (*frame_recv_it).first->GetSize ();
        }
    }

  if ((m_max_data < m_rxBuffer->Size () + validPacketSize))
    {
      return true;
    }
  return false;
}

uint32_t
QuicSocketBase::GetMaxStreamId () const
{
  return std::max (m_initial_max_stream_id_bidi, m_initial_max_stream_id_uni);
}

uint32_t
QuicSocketBase::GetMaxStreamIdBidirectional () const
{
  return m_initial_max_stream_id_bidi;
}

uint32_t
QuicSocketBase::GetMaxStreamIdUnidirectional () const
{
  return m_initial_max_stream_id_uni;
}

bool
QuicSocketBase::CouldContainTransportParameters () const
{
  return m_couldContainTransportParameters;
}

void
QuicSocketBase::SetCongestionControlAlgorithm (Ptr<TcpCongestionOps> algo)
{
  NS_LOG_FUNCTION (this << algo);
  if (DynamicCast<QuicCongestionOps> (algo) != nullptr)
    {
      NS_LOG_INFO ("Non-legacy congestion control");
      m_quicCongestionControlLegacy = false;
    }
  else
    {
      NS_LOG_INFO (
        "Legacy congestion control, using only TCP standard functions");
      m_quicCongestionControlLegacy = true;
    }
  m_congestionControl = algo;
}

void
QuicSocketBase::SetSocketSndBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_socketTxBufferSize = size;
  m_txBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicSocketBase::GetSocketSndBufSize (void) const
{
  return m_txBuffer->GetMaxBufferSize ();
}

void
QuicSocketBase::SetSocketRcvBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_socketRxBufferSize = size;
  m_rxBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicSocketBase::GetSocketRcvBufSize (void) const
{
  return m_rxBuffer->GetMaxBufferSize ();
}

void
QuicSocketBase::UpdateCwnd (uint32_t oldValue, uint32_t newValue)
{
  m_cWndTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateSsThresh (uint32_t oldValue, uint32_t newValue)
{
  m_ssThTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateCongState (TcpSocketState::TcpCongState_t oldValue,
                                 TcpSocketState::TcpCongState_t newValue)
{
  m_congStateTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateNextTxSequence (SequenceNumber32 oldValue,
                                      SequenceNumber32 newValue)

{
  m_nextTxSequenceTrace (oldValue.GetValue (), newValue.GetValue ());
}

void
QuicSocketBase::UpdateHighTxMark (SequenceNumber32 oldValue, SequenceNumber32 newValue)
{
  m_highTxMarkTrace (oldValue.GetValue (), newValue.GetValue ());
}

void
QuicSocketBase::SetInitialSSThresh (uint32_t threshold)
{
  NS_ABORT_MSG_UNLESS ( (m_socketState == IDLE) || threshold == m_tcb->m_initialSsThresh,
                        "QuicSocketBase::SetSSThresh() cannot change initial ssThresh after connection started.");

  m_tcb->m_initialSsThresh = threshold;
}

uint32_t
QuicSocketBase::GetInitialSSThresh (void) const
{
  return m_tcb->m_initialSsThresh;
}

void
QuicSocketBase::SetInitialPacketSize (uint32_t size)
{
  NS_ABORT_MSG_IF (size < 1200, "The size of the initial packet should be at least 1200 bytes");
  m_initialPacketSize = size;
}

uint32_t
QuicSocketBase::GetInitialPacketSize () const
{
  return m_initialPacketSize;
}

void QuicSocketBase::SetLatency (uint32_t streamId, Time latency)
{
  m_txBuffer->SetLatency (streamId, latency);
}

Time QuicSocketBase::GetLatency (uint32_t streamId)
{
  return m_txBuffer->GetLatency (streamId);
}

void QuicSocketBase::SetDefaultLatency (Time latency)
{
  m_txBuffer->SetDefaultLatency (latency);
}

Time QuicSocketBase::GetDefaultLatency ()
{
  return m_txBuffer->GetDefaultLatency ();
}

void
QuicSocketBase::MaybeUpdateDestCid (void)
{
  // msquic QuicSendFlush: after DestCidUpdateIdleTimeoutMs without a flush the id changes, so that traffic
  // after a long pause cannot be linked to the traffic before it
  if (m_paths.empty () || !m_destCidUpdateIdleTimeout.IsStrictlyPositive () || m_lastPacketSent.IsZero ())
    {
      return;
    }
  QuicPath &active = m_paths.front ();
  if (Simulator::Now () - m_lastPacketSent >= m_destCidUpdateIdleTimeout && !active.initiatedCidUpdate)
    {
      if (RetireCurrentDestCid (active))
        {
          active.initiatedCidUpdate = true;
        }
    }
}

void
QuicSocketBase::BeginSendFlush (void)
{
  MaybeUpdateDestCid ();
  Time now = Simulator::Now ();
  Time srtt = m_tcb->m_smoothedRtt;
  uint32_t cwnd = m_tcb->m_cWnd.Get ();
  uint32_t inFlight = m_tcb->m_bytesInFlight.Get ();
  if (inFlight >= cwnd)
    {
      m_flushAllowance = 0;
    }
  else if (!m_tcb->m_pacing || !m_lastFlushValid || srtt <= Seconds (0) || srtt < MicroSeconds (1000))
    {
      m_flushAllowance = cwnd - inFlight;
    }
  else
    {
      uint64_t est;
      if (cwnd < m_tcb->m_ssThresh)
        {
          est = std::min<uint64_t> ((uint64_t) cwnd << 1, m_tcb->m_ssThresh);
        }
      else
        {
          est = cwnd + (cwnd >> 2);
        }
      uint64_t dtUs = (now - m_lastFlushTime).GetMicroSeconds ();
      uint64_t allowance = m_lastSendAllowance + est * dtUs / (uint64_t) srtt.GetMicroSeconds ();
      m_flushAllowance = std::min<uint64_t> (allowance, cwnd - inFlight);
      m_lastSendAllowance = (uint32_t) m_flushAllowance;
    }
  m_lastFlushTime = now;
  m_lastFlushValid = true;
}

void
QuicSocketBase::ConsumeSendAllowance (uint32_t bytes)
{
  if (m_flushAllowance != UINT64_MAX)
    {
      m_flushAllowance = (bytes >= m_flushAllowance) ? 0 : m_flushAllowance - bytes;
    }
  m_lastSendAllowance = (bytes >= m_lastSendAllowance) ? 0 : m_lastSendAllowance - bytes;
}

void
QuicSocketBase::NotifyPacingPerformed (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("Pacing timer expired, try sending a packet");
  SendPendingData (m_connected);
}

bool
QuicSocketBase::ResetStream (uint64_t streamId, uint16_t errorCode)
{
  NS_LOG_FUNCTION (this << streamId << errorCode);
  return m_quicl5 != nullptr && m_quicl5->ResetStream (streamId, errorCode);
}

bool
QuicSocketBase::StopSending (uint64_t streamId, uint16_t errorCode)
{
  NS_LOG_FUNCTION (this << streamId << errorCode);
  return m_quicl5 != nullptr && m_quicl5->StopSendingOnStream (streamId, errorCode);
}

void
QuicSocketBase::SetStreamPriority (uint64_t streamId, uint16_t priority)
{
  NS_LOG_FUNCTION (this << streamId << priority);
  m_streamPriorities[streamId] = priority;
  if (m_txBuffer != nullptr && m_txBuffer->GetScheduler () != nullptr)
    {
      m_txBuffer->GetScheduler ()->SetStreamPriority (streamId, priority);
    }
}

void
QuicSocketBase::SetStreamBacklog (uint64_t streamId, bool backlogged)
{
  if (m_txBuffer != nullptr && m_txBuffer->GetScheduler () != nullptr)
    {
      m_txBuffer->GetScheduler ()->OnStreamBacklog (streamId, backlogged);
    }
}

void
QuicSocketBase::StartMtuDiscovery (void)
{
  if (m_socketState != OPEN || m_pmtudSearchDone)
    {
      return;
    }
  uint32_t mtu = m_tcb->m_segmentSize + kPmtudOverhead;
  uint32_t maxMtu = m_pmtudMaxSeg + kPmtudOverhead;
  m_pmtudProbeMtu = std::min (mtu + 80, maxMtu);
  if (m_pmtudProbeMtu <= mtu)
    {
      m_pmtudSearchDone = true;
      return;
    }
  m_pmtudProbeCount = 0;
  SendMtuProbe ();
}

void
QuicSocketBase::SendMtuProbe (void)
{
  if (m_socketState != OPEN || m_pmtudSearchDone)
    {
      return;
    }
  SequenceNumber32 pn = ++m_tcb->m_nextTxSequence;
  QuicHeader head = QuicHeader::CreateShort (GetDestCid (), pn, !m_omit_connection_id, m_keyPhase, m_spinBit);
  // IP MTU = IP header + UDP header + QUIC header + frames: PING plus PADDING up to the probe size
  uint32_t fixed = 28 + head.GetSerializedSize ();
  QuicSubheader ping = QuicSubheader::CreatePing ();
  uint32_t overhead = fixed + ping.GetSerializedSize ();
  uint32_t padding = (m_pmtudProbeMtu > overhead) ? m_pmtudProbeMtu - overhead : 0;
  Ptr<Packet> p = Create<Packet> (padding);
  p->AddHeader (ping);
  NS_LOG_INFO ("MTU probe " << m_pmtudProbeMtu << " (attempt " << m_pmtudProbeCount + 1 << ")");
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);
  m_pmtudProbePn = pn.GetValue ();
  Time pto = m_tcb->m_smoothedRtt > Seconds (0)
             ? m_tcb->m_smoothedRtt + std::max (4 * m_tcb->m_rttVar, MilliSeconds (1)) + m_tcb->m_maxAckDelay
             : 2 * m_tcb->m_kDefaultInitialRtt;
  m_pmtudTimeout.Cancel ();
  m_pmtudTimeout = Simulator::Schedule (pto, &QuicSocketBase::OnMtuProbeTimeout, this);
}

void
QuicSocketBase::OnMtuProbeTimeout (void)
{
  m_pmtudProbePn = 0;
  if (++m_pmtudProbeCount >= 3)
    {
      NS_LOG_INFO ("MTU search complete at " << m_tcb->m_segmentSize + kPmtudOverhead);
      m_pmtudSearchDone = true;
      return;
    }
  SendMtuProbe ();
}

void
QuicSocketBase::OnMtuProbeAcked (void)
{
  m_pmtudTimeout.Cancel ();
  m_pmtudProbePn = 0;
  uint32_t seg = m_pmtudProbeMtu - kPmtudOverhead;
  m_tcb->m_segmentSize = seg;
  m_tcb->m_kMinimumWindow = 2 * seg;
  NS_LOG_INFO ("Path MTU raised to " << m_pmtudProbeMtu);
  if (m_pmtudProbeMtu >= m_pmtudMaxSeg + kPmtudOverhead)
    {
      m_pmtudSearchDone = true;
      return;
    }
  StartMtuDiscovery ();
}

uint32_t
QuicSocketBase::AckToleranceLimit () const
{
  if (m_ackToleranceCwndDivisor == 0)
    {
      return 255;
    }
  uint32_t packets = m_tcb->m_cWnd.Get () / std::max<uint32_t> (m_tcb->m_segmentSize, 1);
  return std::max<uint32_t> (2, std::min<uint32_t> (packets / m_ackToleranceCwndDivisor, 255));
}

void
QuicSocketBase::UpdatePeerAckTolerance (uint8_t tolerance)
{
  // msquic QuicConnUpdatePeerPacketTolerance
  if (!m_peerSupportsAckFreq || m_peerAckTolerance == tolerance || m_socketState != OPEN)
    {
      return;
    }
  NS_LOG_INFO ("Updating peer packet tolerance to " << (uint32_t) tolerance);
  ++m_sendAckFreqSeq;
  m_peerAckTolerance = tolerance;
  uint64_t delayUs = m_tcb->m_maxAckDelay.IsStrictlyPositive () ? m_tcb->m_maxAckDelay.GetMicroSeconds () : 25000;
  Ptr<Packet> p = Create<Packet> (0);
  p->AddHeader (QuicSubheader::CreateAckFrequency (m_sendAckFreqSeq, tolerance, delayUs, m_peerAckReordering));
  AppendingTx (p);
}

void
QuicSocketBase::HandleStatelessReset (void)
{
  NS_LOG_FUNCTION (this);
  if (m_socketState == IDLE || m_socketState == CLOSING)
    {
      return;
    }
  // msquic QuicConnProcessUdpDatagrams: the connection is closed silently, without a CONNECTION_CLOSE,
  // and the application hears of a transport shutdown
  m_tcb->m_lossDetectionAlarm.Cancel ();
  m_idleTimeoutEvent.Cancel ();
  SetState (CLOSING);
  m_closeNotified = true;
  NotifyErrorClose ();
  Simulator::ScheduleNow (&QuicSocketBase::DoClose, this);
}

bool
QuicSocketBase::FinishStream (uint64_t streamId)
{
  NS_LOG_FUNCTION (this << streamId);
  return m_quicl5 != nullptr && m_quicl5->FinishStream (streamId);
}

// ------------------------------------------------------------------------------------------------
// Connection ids and paths
// ------------------------------------------------------------------------------------------------

void
QuicSocketBase::InitPaths (void)
{
  if (!m_paths.empty ())
    {
      return;
    }
  QuicPath first;
  first.id = 0;
  first.active = true;
  first.validated = true;
  first.gotValidPacket = true;
  first.allowance = UINT64_MAX;
  first.destCidSequence = 0;
  Ptr<Socket> udp;
  Address remote;
  if (m_quicl4->GetPath (this, udp, remote))
    {
      first.udp = udp;
      first.remote = remote;
    }
  m_paths.push_back (first);

  // sequence number 0 of both directions is the id chosen at connection start
  QuicCidEntry src;
  src.sequence = 0;
  src.id = m_connectionId;
  src.used = true;
  m_srcCids.push_back (src);
  QuicCidEntry dst = src;
  m_dstCids.push_back (dst);
  m_destCid = m_connectionId;
}

QuicSocketBase::QuicCidEntry *
QuicSocketBase::FindSourceCid (uint64_t id)
{
  for (auto &cid : m_srcCids)
    {
      if (cid.id == id && !cid.retired)
        {
          return &cid;
        }
    }
  return nullptr;
}

QuicSocketBase::QuicCidEntry *
QuicSocketBase::UnusedDestCid (void)
{
  for (auto &cid : m_dstCids)
    {
      if (!cid.retired && !cid.used)
        {
          return &cid;
        }
    }
  return nullptr;
}

uint32_t
QuicSocketBase::GetActiveSourceCids (void) const
{
  uint32_t n = 0;
  for (auto &cid : m_srcCids)
    {
      n += cid.retired ? 0 : 1;
    }
  return n;
}

uint32_t
QuicSocketBase::GetActiveDestCids (void) const
{
  uint32_t n = 0;
  for (auto &cid : m_dstCids)
    {
      n += cid.retired ? 0 : 1;
    }
  return n;
}

void
QuicSocketBase::SendControlFrame (const QuicSubheader &sub)
{
  Ptr<Packet> p = Create<Packet> (0);
  p->AddHeader (sub);
  AppendingTx (p);
}

void
QuicSocketBase::IssueSourceCid (void)
{
  // msquic QuicConnGenerateNewSourceCid: a random id with its own stateless reset token
  QuicCidEntry cid;
  cid.sequence = m_nextSrcCidSequence++;
  cid.id = m_quicl4->AllocateConnectionId ();
  m_quicl4->GenerateStatelessResetToken (cid.id, cid.tokenHi, cid.tokenLo);
  m_srcCids.push_back (cid);
  m_quicl4->RegisterConnectionId (cid.id, this);
  SendControlFrame (QuicSubheader::CreateNewConnectionId (cid.sequence, 0, cid.id, cid.tokenHi, cid.tokenLo));
}

void
QuicSocketBase::IssueSourceCids (void)
{
  // up to the limit the peer announced (and our own maximum): sequence 0 counts as one
  uint32_t limit = std::min<uint32_t> (m_peerActiveCidLimit, kActiveCidLimit);
  while (GetActiveSourceCids () < limit)
    {
      IssueSourceCid ();
    }
}

void
QuicSocketBase::RetireDestCid (QuicCidEntry &cid)
{
  if (cid.retired)
    {
      return;
    }
  cid.retired = true;
  SendControlFrame (QuicSubheader::CreateRetireConnectionId (cid.sequence));
}

bool
QuicSocketBase::RetireCurrentDestCid (QuicPath &path)
{
  // msquic QuicConnRetireCurrentDestCid: switch to an unused id, retire the one that was in use
  QuicCidEntry *fresh = UnusedDestCid ();
  if (fresh == nullptr)
    {
      NS_LOG_WARN ("Can't retire the current destination id: no replacement");
      return false;
    }
  for (auto &cid : m_dstCids)
    {
      if ((int64_t) cid.sequence == path.destCidSequence)
        {
          RetireDestCid (cid);
        }
    }
  fresh->used = true;
  path.destCidSequence = (int64_t) fresh->sequence;
  if (path.active)
    {
      m_destCid = fresh->id;
    }
  return true;
}

uint64_t
QuicSocketBase::PathDestCid (QuicPath &path)
{
  if (path.destCidSequence < 0)
    {
      QuicCidEntry *fresh = UnusedDestCid ();
      if (fresh == nullptr)
        {
          return GetDestCid ();
        }
      fresh->used = true;
      path.destCidSequence = (int64_t) fresh->sequence;
    }
  for (auto &cid : m_dstCids)
    {
      if ((int64_t) cid.sequence == path.destCidSequence && !cid.retired)
        {
          return cid.id;
        }
    }
  return GetDestCid ();
}

bool
QuicSocketBase::IsProbingFrame (const QuicSubheader &sub) const
{
  // RFC 9000 s9.1
  return sub.GetFrameType () == QuicSubheader::PADDING || sub.IsPathChallenge () || sub.IsPathResponse ()
         || sub.IsNewConnectionId ();
}

void
QuicSocketBase::NoteFrame (const QuicSubheader &sub)
{
  if (!IsProbingFrame (sub))
    {
      m_rxNonProbing = true;
    }
}

bool
QuicSocketBase::OnPacketOnPath (Ptr<Socket> udp, const Address &from, uint32_t bytes, uint64_t connectionId)
{
  m_rxPathIndex = -1;
  m_rxNonProbing = false;
  m_rxDcid = connectionId;
  if (m_paths.empty () || !m_tcb->m_handshakeConfirmed)
    {
      // one path until the handshake is confirmed (msquic ignores packets from other addresses then)
      return true;
    }
  InetSocketAddress remote = InetSocketAddress::ConvertFrom (from);
  for (size_t i = 0; i < m_paths.size (); ++i)
    {
      if (m_paths[i].udp == udp && InetSocketAddress::ConvertFrom (m_paths[i].remote).GetIpv4 () == remote.GetIpv4 ()
          && InetSocketAddress::ConvertFrom (m_paths[i].remote).GetPort () == remote.GetPort ())
        {
          m_rxPathIndex = (int) i;
          break;
        }
    }
  if (m_rxPathIndex < 0)
    {
      if (m_paths.size () >= kMaxPaths)
        {
          // msquic first drops an old path that is only a rebind of this one
          bool freed = false;
          for (size_t i = m_paths.size (); i-- > 1 && !freed;)
            {
              if (InetSocketAddress::ConvertFrom (m_paths[i].remote).GetIpv4 () == remote.GetIpv4 ())
                {
                  RemovePath (i);
                  freed = true;
                }
            }
          if (!freed)
            {
              return false;
            }
        }
      QuicPath path;
      path.id = m_nextPathId++;
      path.remote = from;
      path.udp = udp;
      path.segSize = 0;
      // the new path is kept right after the active one
      m_paths.insert (m_paths.begin () + 1, path);
      m_rxPathIndex = 1;
      NS_LOG_INFO ("New path " << path.id << " from " << remote.GetIpv4 () << ":" << remote.GetPort ());
    }
  QuicPath &p = m_paths[m_rxPathIndex];
  if (!p.validated)
    {
      // amplification protection: three times what the peer sent on this path (QuicPathSetAllowance)
      p.allowance = (p.allowance > UINT64_MAX - 3ULL * bytes) ? UINT64_MAX : p.allowance + 3ULL * bytes;
      if (p.sendChallenge && p.lastChallengeSent.IsZero () && p.allowance >= kMinSendAllowance)
        {
          SendPathChallenge (p);
        }
      if (m_sendPendingDataEvent.IsExpired ())
        {
          m_sendPendingDataEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendPendingData, this, m_connected);
        }
    }
  return true;
}

Time
QuicSocketBase::PathProbeTimeout (void) const
{
  Time srtt = m_tcb->m_smoothedRtt > Seconds (0) ? m_tcb->m_smoothedRtt : m_tcb->m_kDefaultInitialRtt;
  Time var = m_tcb->m_smoothedRtt > Seconds (0) ? m_tcb->m_rttVar : m_tcb->m_kDefaultInitialRtt / 2;
  return srtt + std::max (4 * var, MilliSeconds (1)) + m_tcb->m_maxAckDelay;
}

Time
QuicSocketBase::PathValidationTimeout (void) const
{
  // msquic QuicConnPathValidationTimeoutUs: three probe timeouts, at least six initial RTTs
  return std::max (3 * PathProbeTimeout (), 6 * m_tcb->m_kDefaultInitialRtt);
}

void
QuicSocketBase::SendPathChallenge (QuicPath &path)
{
  if (path.udp == nullptr || path.allowance < kMinSendAllowance)
    {
      NS_LOG_INFO ("PATH_CHALLENGE held back on path " << path.id << " (allowance " << path.allowance << ")");
      path.sendChallenge = true;        // sent as soon as the path allows
      return;
    }
  QuicSubheader frame = QuicSubheader::CreatePathChallenge (path.challenge);
  SequenceNumber32 pn = ++m_tcb->m_nextTxSequence;
  QuicHeader head = QuicHeader::CreateShort (PathDestCid (path), pn, !m_omit_connection_id, m_keyPhase, m_spinBit);

  // The packet is padded to the path MTU to validate it (QuicSendPathChallenges), within what the path allows
  uint32_t segment = path.active ? m_tcb->m_segmentSize : (path.segSize ? path.segSize : kPmtudInitialMtu - kPmtudOverhead);
  uint32_t total = (uint32_t) std::min<uint64_t> (segment, path.allowance);   // the whole packet, headers included
  uint32_t used = frame.GetSerializedSize () + head.GetSerializedSize ();
  Ptr<Packet> p = Create<Packet> (0);
  Ptr<Packet> pad = Create<Packet> (total > used ? total - used : 0);
  p->AddAtEnd (pad);
  p->AddHeader (frame);
  if (!path.validated)
    {
      uint64_t size = p->GetSize () + head.GetSerializedSize ();
      path.allowance = (size >= path.allowance) ? 0 : path.allowance - size;
    }
  path.lastChallengeSent = Simulator::Now ();
  NS_LOG_INFO ("PATH_CHALLENGE on path " << path.id << " (" << p->GetSize () << " bytes, allowance left " << path.allowance << ")");
  m_quicl4->SendPacketOnPath (p, head, path.udp, path.remote);
  m_txTrace (p, head, this);
}

void
QuicSocketBase::SendPathResponse (QuicPath &path, uint64_t data)
{
  if (path.udp == nullptr)
    {
      return;
    }
  Ptr<Packet> p = Create<Packet> (0);
  p->AddHeader (QuicSubheader::CreatePathResponse (data));
  SequenceNumber32 pn = ++m_tcb->m_nextTxSequence;
  QuicHeader head = QuicHeader::CreateShort (PathDestCid (path), pn, !m_omit_connection_id, m_keyPhase, m_spinBit);
  NS_LOG_INFO ("PATH_RESPONSE on path " << path.id);
  m_quicl4->SendPacketOnPath (p, head, path.udp, path.remote);
  m_txTrace (p, head, this);
}

void
QuicSocketBase::ArmPathTimer (void)
{
  m_pathTimer.Cancel ();
  bool validating = false;
  for (auto &p : m_paths)
    {
      validating = validating || (!p.validated && p.validationStart.IsStrictlyPositive ());
    }
  if (validating)
    {
      m_pathTimer = Simulator::Schedule (PathProbeTimeout (), &QuicSocketBase::OnPathValidationTimer, this);
    }
}

void
QuicSocketBase::OnPathValidationTimer (void)
{
  Time now = Simulator::Now ();
  for (size_t i = m_paths.size (); i-- > 0;)
    {
      QuicPath &p = m_paths[i];
      if (p.validated || !p.validationStart.IsStrictlyPositive ())
        {
          continue;
        }
      if (now - p.validationStart > PathValidationTimeout ())
        {
          NS_LOG_INFO ("Path " << p.id << " validation timed out");
          if (m_paths.size () == 1)
            {
              // the last path failed: nothing left to talk over
              m_tcb->m_lossDetectionAlarm.Cancel ();
              SetState (CLOSING);
              m_closeNotified = true;
              NotifyErrorClose ();
              Simulator::ScheduleNow (&QuicSocketBase::DoClose, this);
              return;
            }
          RemovePath (i);
        }
      else if (p.sendChallenge)
        {
          SendPathChallenge (p);      // the challenge is repeated until it is answered
        }
    }
  ArmPathTimer ();
}

void
QuicSocketBase::RemovePath (size_t index)
{
  if (index >= m_paths.size () || m_paths[index].active)
    {
      return;
    }
  m_paths.erase (m_paths.begin () + index);
  m_rxPathIndex = -1;
}

void
QuicSocketBase::SetPathValid (QuicPath &path)
{
  if (path.validated)
    {
      return;
    }
  path.validated = true;
  path.sendChallenge = false;
  path.validationStart = Seconds (0);
  path.allowance = UINT64_MAX;
  NS_LOG_INFO ("Path " << path.id << " validated");
  if (path.active)
    {
      // msquic QuicMtuDiscoveryPeerValidated: the validated active path searches its MTU again
      m_pmtudSearchDone = false;
      Simulator::ScheduleNow (&QuicSocketBase::StartMtuDiscovery, this);
      if (m_sendPendingDataEvent.IsExpired ())
        {
          m_sendPendingDataEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendPendingData, this, m_connected);
        }
    }
  ArmPathTimer ();
}

void
QuicSocketBase::ActivatePath (size_t index)
{
  if (index == 0 || index >= m_paths.size ())
    {
      return;
    }
  QuicPath &old = m_paths.front ();
  QuicPath incoming = m_paths[index];
  InetSocketAddress a = InetSocketAddress::ConvertFrom (old.remote);
  InetSocketAddress b = InetSocketAddress::ConvertFrom (incoming.remote);
  // only the UDP port changed (a NAT rebinding): msquic keeps the congestion state in that case
  bool portOnly = a.GetIpv4 () == b.GetIpv4 () && a.GetPort () != b.GetPort ();

  // the old path keeps its own transport state while it is not active
  old.segSize = m_tcb->m_segmentSize;
  old.maxSeg = m_pmtudMaxSeg;
  old.mtuSearchDone = m_pmtudSearchDone;
  old.mtuStarted = m_pmtudStarted;
  old.active = false;
  incoming.active = true;
  m_paths[index] = old;
  m_paths.front () = incoming;
  QuicPath &now = m_paths.front ();
  NS_LOG_INFO ("Path " << now.id << " is now the active path (rebind " << portOnly << ")");

  m_quicl4->SetPath (this, now.udp, now.remote);
  m_destCid = PathDestCid (now);

  // a new path starts from the minimum MTU and a fresh RTT estimate (QuicPathInitialize)
  uint32_t seg = now.segSize ? now.segSize : kPmtudInitialMtu - kPmtudOverhead;
  uint32_t maxSeg = now.maxSeg ? now.maxSeg : m_pmtudMaxSeg;
  m_tcb->m_segmentSize = seg;
  m_tcb->m_kMinimumWindow = 2 * seg;
  m_tcb->m_initialCWnd = std::min (10 * seg, std::max ((uint32_t) 14720, 2 * seg));
  m_pmtudMaxSeg = maxSeg;
  m_pmtudSearchDone = true;     // the search starts when the path is validated
  m_pmtudStarted = true;
  m_tcb->m_smoothedRtt = Seconds (0);
  m_tcb->m_rttVar = Seconds (0);
  m_tcb->m_latestRtt = Seconds (0);
  if (!portOnly)
    {
      DynamicCast<QuicCongestionOps> (m_congestionControl)->OnPathChange (m_tcb);
    }
  if (now.validated)
    {
      m_pmtudSearchDone = false;
      Simulator::ScheduleNow (&QuicSocketBase::StartMtuDiscovery, this);
    }
  if (m_sendPendingDataEvent.IsExpired ())
    {
      m_sendPendingDataEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendPendingData, this, m_connected);
    }
}

void
QuicSocketBase::RecvPostProcessing (void)
{
  if (m_rxPathIndex < 0 || m_rxPathIndex >= (int) m_paths.size ())
    {
      return;
    }
  size_t index = (size_t) m_rxPathIndex;
  QuicPath &path = m_paths[index];

  bool peerUpdatedCid = false;
  QuicCidEntry *src = FindSourceCid (m_rxDcid);
  if (src != nullptr && !src->used)
    {
      src->used = true;
      peerUpdatedCid = src->sequence != 0;
    }

  if (!path.gotValidPacket)
    {
      path.gotValidPacket = true;
      if (!path.active)
        {
          // first valid packet on a new path: challenge it, and the active path as well
          path.sendChallenge = true;
          path.validationStart = Simulator::Now ();
          Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable> ();
          path.challenge = ((uint64_t) rng->GetInteger (0, 0xffffffffu) << 32) | rng->GetInteger (0, 0xffffffffu);
          QuicPath &active = m_paths.front ();
          if (active.validated)
            {
              active.validated = false;
              active.sendChallenge = true;
              active.validationStart = Simulator::Now ();
              active.challenge = ((uint64_t) rng->GetInteger (0, 0xffffffffu) << 32) | rng->GetInteger (0, 0xffffffffu);
              SendPathChallenge (active);
            }
          SendPathChallenge (path);
          ArmPathTimer ();
        }
    }
  else if (peerUpdatedCid)
    {
      // the peer switched to one of its new ids: answer with a switch of our own
      if (!path.initiatedCidUpdate)
        {
          RetireCurrentDestCid (path);
        }
      else
        {
          path.initiatedCidUpdate = false;
        }
    }

  // non-probing frames on a new path: the peer moved
  if (m_rxNonProbing && m_latestRecvPn == m_receivedPacketNumbers.Largest () && !path.active)
    {
      ActivatePath (index);
    }
  m_rxPathIndex = -1;
}

bool
QuicSocketBase::Migrate (const Address &newLocal)
{
  NS_LOG_FUNCTION (this);
  // RFC 9000 s18.2: the peer asked not to be migrated; a migration on purpose is then forbidden
  if (m_isServerSide || m_socketState != OPEN || !m_tcb->m_handshakeConfirmed || m_paths.empty ()
      || m_peerDisablesMigration)
    {
      return false;
    }
  Ptr<Socket> udp = m_quicl4->RebindLocalAddress (this, newLocal);
  if (udp == nullptr)
    {
      return false;
    }
  m_paths.front ().udp = udp;
  // The peer learns the new address from the next packet, and a PING makes sure there is one. Like any probe of
  // a new path (RFC 9000 s8.2.1) it is expanded to the smallest datagram size, 1200 bytes: the peer may send only
  // three times what it receives on a path it has not validated, and a bare PING would leave it room for a single
  // PATH_CHALLENGE, so that one lost challenge (or response) could never be repeated
  Ptr<Packet> probe = Create<Packet> (MIN_INITIAL_PACKET_SIZE - 11);   // 11: the PING and the short header
  probe->AddHeader (QuicSubheader::CreatePing ());
  AppendingTx (probe);
  return true;
}

}
