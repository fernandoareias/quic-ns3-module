/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 */

#include "quic-socket-tx-buffer.h"
#include "quic-stream.h"

namespace {
/** Copy a byte range into a fresh packet (avoids packet-metadata fragmentation issues). */
ns3::Ptr<ns3::Packet>
CopyRange (ns3::Ptr<ns3::Packet> p, uint32_t start, uint32_t len)
{
  std::vector<uint8_t> all (p->GetSize ());
  if (!all.empty ())
    {
      p->CopyData (all.data (), all.size ());
    }
  if (len == 0)
    {
      return ns3::Create<ns3::Packet> ();
    }
  return ns3::Create<ns3::Packet> (all.data () + start, len);
}
}

#include <algorithm>
#include <iostream>
#include <sstream>
#include "ns3/simulator.h"

#include "ns3/packet.h"
#include "ns3/log.h"
#include "ns3/abort.h"
#include "quic-subheader.h"
#include "quic-socket-base.h"
#include "quic-socket-tx-scheduler.h"
#include "quic-socket-tx-edf-scheduler.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketTxBuffer");

TypeId QuicSocketTxItem::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketTxItem")
    .SetParent<Object>()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketTxItem>()
//    .AddTraceSource ("UnackSequence",
//                     "First unacknowledged sequence number (SND.UNA)",
//                     MakeTraceSourceAccessor (&QuicSocketTxBuffer::m_sentSize),
//                     "ns3::SequenceNumber32TracedValueCallback")
  ;
  return tid;
}

QuicSocketTxItem::QuicSocketTxItem () 
  : m_packet (0), 
    m_packetNumber (0), 
    m_lost (false), 
    m_retrans (false), 
    m_sacked (false), 
    m_acked (false), 
    m_isStream (false), 
    m_isStream0 (false), 
    m_lastSent (Time::Min ())
{
  m_generated = Simulator::Now ();
}

QuicSocketTxItem::QuicSocketTxItem (const QuicSocketTxItem &other)
  : m_packet (other.m_packet),
    m_packetNumber (other.m_packetNumber), 
    m_lost (other.m_lost), 
    m_retrans (other.m_retrans), 
    m_sacked (other.m_sacked), 
    m_acked (other.m_acked), 
    m_isStream (other.m_isStream), 
    m_isStream0 (other.m_isStream0),
    m_lastSent (other.m_lastSent),
    m_generated (other.m_generated),
    m_ackEliciting (other.m_ackEliciting)
{
  m_packet = other.m_packet->Copy ();
}

void QuicSocketTxItem::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this);
  os << "[SN " << m_packetNumber.GetValue () << " - Last Sent: " << m_lastSent
     << " size " << m_packet->GetSize () << "]";

  if (m_lost)
    {
      os << "|lost|";
    }
  if (m_retrans)
    {
      os << "|retr|";
    }
  if (m_sacked)
    {
      os << "|ackd|";
    }
}

void QuicSocketTxItem::MergeItems (QuicSocketTxItem &t1, QuicSocketTxItem &t2)
{

  if (t1.m_sacked == true && t2.m_sacked == true)
    {
      t1.m_sacked = true;
    }
  else
    {
      t1.m_sacked = false;
    }
  if (t1.m_acked == true && t2.m_acked == true)
    {
      t1.m_acked = true;
    }
  else
    {
      t1.m_acked = false;
    }

  if (t2.m_retrans == true && t1.m_retrans == false)
    {
      t1.m_retrans = true;
    }
  if (t1.m_lastSent < t2.m_lastSent)
    {
      t1.m_lastSent = t2.m_lastSent;
    }
  if (t2.m_lost)
    {
      t1.m_lost = true;
    }
  if (t1.m_ackTime > t2.m_ackTime)
    {
      t1.m_ackTime = t2.m_ackTime;
    }
  if (t1.m_generated > t2.m_generated)
    {
      t1.m_generated = t2.m_generated;
    }

  t1.m_packet->AddAtEnd (t2.m_packet);
}

void QuicSocketTxItem::SplitItems (QuicSocketTxItem &t1, QuicSocketTxItem &t2,
                                   uint32_t size)
{
  uint32_t initialSize = t1.m_packet->GetSize ();

  t2.m_sacked = t1.m_sacked;
  t2.m_retrans = t1.m_retrans;
  t2.m_lastSent = t1.m_lastSent;
  t2.m_lost = t1.m_lost;
  if (t1.m_lastSent < t2.m_lastSent)
    {
      t1.m_lastSent = t2.m_lastSent;
    }
  if (t2.m_lost)
    {
      t1.m_lost = true;
    }
  t2.m_generated = t1.m_generated;
  // Copy the packet into t2
  t2.m_packet = t1.m_packet->Copy ();
  // Remove the first size bytes from t2
  t2.m_packet->RemoveAtStart (size);

  // Change subheader
  QuicSubheader qsb;
  t1.m_packet->RemoveHeader (qsb);
  qsb.SetLength (t1.m_packet->GetSize () - size);
  t1.m_packet->AddHeader (qsb);

  NS_ASSERT_MSG (t2.m_packet->GetSize () == initialSize - size,
                 "Wrong size " << t2.m_packet->GetSize ());
  qsb.SetLength (t2.m_packet->GetSize ());
  t2.m_packet->AddHeader (qsb);
  // Remove the bytes from size to end from t1
  t1.m_packet->RemoveAtEnd (t1.m_packet->GetSize () - size);
  NS_ASSERT_MSG (t1.m_packet->GetSize () == size,
                 "Wrong size " << t1.m_packet->GetSize ());
}

NS_OBJECT_ENSURE_REGISTERED (QuicSocketTxBuffer);

TypeId QuicSocketTxBuffer::GetTypeId (void)
{
  static TypeId tid =
    TypeId ("ns3::QuicSocketTxBuffer").SetParent<Object>().SetGroupName (
      "Internet").AddConstructor<QuicSocketTxBuffer>()
//    .AddTraceSource ("UnackSequence",
//                     "First unacknowledged sequence number (SND.UNA)",
//                     MakeTraceSourceAccessor (&QuicSocketTxBuffer::m_sentSize),
//                     "ns3::SequenceNumber32TracedValueCallback")
  ;
  return tid;
}

QuicSocketTxBuffer::QuicSocketTxBuffer () :
  m_maxBuffer (32768), m_streamZeroSize (0), m_sentSize (0), m_numFrameStream0InBuffer (
    0)
{
  m_streamZeroList = QuicTxPacketList ();
  m_sentList = QuicTxPacketList ();
  m_inFlightValid = false;
}

QuicSocketTxBuffer::~QuicSocketTxBuffer (void)
{
  QuicTxPacketList::iterator it;

  m_sentList = QuicTxPacketList ();
  m_inFlightValid = false;
  m_streamZeroList = QuicTxPacketList ();
  m_sentSize = 0;
  m_streamZeroSize = 0;
}

void QuicSocketTxBuffer::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this);
  QuicSocketTxBuffer::QuicTxPacketList::const_iterator it;
  std::stringstream ss;
  std::stringstream as;

  for (it = m_sentList.begin (); it != m_sentList.end (); ++it)
    {
      (*it)->Print (ss);
    }

  for (it = m_streamZeroList.begin (); it != m_streamZeroList.end (); ++it)
    {
      (*it)->Print (as);
    }

  os << Simulator::Now ().GetSeconds () << "\nStream 0 list: \n" << as.str ()
     << "\n\nSent list: \n" << ss.str () << "\n\nCurrent Status: "
     << "\nNumber of transmissions = " << m_sentList.size ()
     << "\nSent Size = " << m_sentSize
     << "\nNumber of stream 0 packets waiting = "
     << m_streamZeroList.size () << "\nStream 0 waiting packet size = "
     << m_streamZeroSize;
}

bool QuicSocketTxBuffer::Add (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this << p);
  QuicSubheader qsb;
  uint32_t headerSize = p->PeekHeader (qsb);
  NS_LOG_INFO (
    "Try to append " << p->GetSize () << " bytes " << ", availSize=" << Available () << " offset " << qsb.GetOffset () << " on stream " << qsb.GetStreamId ());

  if (p->GetSize () <= Available ())
    {
      if (p->GetSize () > 0)
        {
          Ptr<QuicSocketTxItem> item = CreateObject<QuicSocketTxItem> ();
          item->m_packet = p;
          // check to which stream this packet belongs to
          bool isStream = false;
          // Handshake data and control frames without a stream (MAX_DATA, MAX_STREAMS, ...) go first
          bool priority = true;
          if (headerSize)
            {
              isStream = qsb.IsStream ();
              bool carriesStreamId = isStream || qsb.IsRstStream () || qsb.IsStopSending ()
                || qsb.IsMaxStreamData () || qsb.IsStreamBlocked ();
              priority = !carriesStreamId || qsb.GetStreamId () == QuicStream::HANDSHAKE_STREAM_ID;
            }
          else
            {
              NS_ABORT_MSG ("No QuicSubheader in this QUIC frame " << p);
            }
          item->m_isStream = isStream;
          item->m_isStream0 = priority;
          m_numFrameStream0InBuffer += priority;
          if (priority)
            {
              m_streamZeroList.insert (m_streamZeroList.end (), item);
              m_streamZeroSize += item->m_packet->GetSize ();
            }
          else
            {
              m_scheduler->Add (item, false);
            }

          NS_LOG_INFO (
            "Update: Application Size = " << m_scheduler->AppSize () << ", offset " << qsb.GetOffset ());
          return true;
        }
      else
        {
          NS_LOG_WARN ("Discarded. Try to insert empty packet.");
          return false;
        }
    }
  NS_LOG_WARN ("Rejected. Not enough room to buffer packet.");
  return false;
}

Ptr<Packet> QuicSocketTxBuffer::NextStream0Sequence (
  const SequenceNumber32 seq)
{
  NS_LOG_FUNCTION (this << seq);

  Ptr<QuicSocketTxItem> outItem = CreateObject<QuicSocketTxItem> ();

  QuicTxPacketList::iterator it = m_streamZeroList.begin ();
  if (it != m_streamZeroList.end ())
    {
      Ptr<Packet> currentPacket = (*it)->m_packet;
      outItem->m_packetNumber = seq;
      outItem->m_lastSent = Now ();
      outItem->m_packet = currentPacket;
      outItem->m_isStream0 = (*it)->m_isStream0;
      m_streamZeroList.erase (it);
      m_streamZeroSize -= currentPacket->GetSize ();
      m_sentList.insert (m_sentList.end (), outItem);
      m_inFlightValid = false;
      m_sentSize += outItem->m_packet->GetSize ();
      --m_numFrameStream0InBuffer;
      Ptr<Packet> toRet = outItem->m_packet;
      return toRet;
    }
  return 0;
}

Ptr<Packet> QuicSocketTxBuffer::NextSequence (uint32_t numBytes,
                                              const SequenceNumber32 seq)
{
  NS_LOG_FUNCTION (this << numBytes << seq);

  Ptr<QuicSocketTxItem> outItem = GetNewSegment (numBytes);

  if (outItem != nullptr)
    {
      NS_LOG_INFO ("Extracting " << outItem->m_packet->GetSize () << " bytes");
      outItem->m_packetNumber = seq;
      outItem->m_lastSent = Now ();
      Ptr<Packet> toRet = outItem->m_packet;
      return toRet;
    }
  else
    {
      NS_LOG_INFO ("Empty packet");
      return Create<Packet>();
    }

}

Ptr<QuicSocketTxItem> QuicSocketTxBuffer::GetNewSegment (uint32_t numBytes)
{
  NS_LOG_FUNCTION (this << numBytes);

  Ptr<QuicSocketTxItem> outItem = m_scheduler->GetNewSegment (numBytes);

  if (outItem->m_packet->GetSize () > 0)
    {
      NS_LOG_LOGIC ("Adding packet to sent buffer");
      m_sentList.insert (m_sentList.end (), outItem);
      m_inFlightValid = false;
      m_sentSize += outItem->m_packet->GetSize ();
    }

  NS_LOG_INFO (
    "Update: Sent Size = " << m_sentSize << " remaining App Size " << m_scheduler->AppSize () << " object size " << outItem->m_packet->GetSize ());

  //Print(std::cout);

  return outItem;
}

std::vector<Ptr<QuicSocketTxItem> > QuicSocketTxBuffer::OnAckUpdate (
  Ptr<TcpSocketState> tcb, const uint32_t largestAcknowledged,
  const std::vector<uint32_t> &additionalAckBlocks,
  const std::vector<uint32_t> &gaps)
{
  NS_LOG_FUNCTION (this);
  std::vector<uint32_t> compAckBlocks = additionalAckBlocks;
  std::vector<uint32_t> compGaps = gaps;

  std::vector<Ptr<QuicSocketTxItem> > newlyAcked;
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));

  compAckBlocks.insert (compAckBlocks.begin (), largestAcknowledged);
  uint32_t ackBlockCount = compAckBlocks.size ();

  std::vector<uint32_t>::const_iterator ack_it = compAckBlocks.begin ();
  std::vector<uint32_t>::const_iterator gap_it = compGaps.begin ();

#ifdef NS3_LOG_ENABLE
  // building the text costs more than the work done with it, so only when the message will be printed
  if (g_log.IsEnabled (ns3::LOG_INFO))
    {
      std::stringstream gap_print;
      for (auto i = gaps.begin (); i != gaps.end (); ++i)
        {
          gap_print << (*i) << " ";
        }
      std::stringstream block_print;
      for (auto i = compAckBlocks.begin (); i != compAckBlocks.end (); ++i)
        {
          block_print << (*i) << " ";
        }
      NS_LOG_INFO (
        "Largest ACK: " << largestAcknowledged << ", blocks: " << block_print.str () << ", gaps: " << gap_print.str ());
    }
#endif

  // Iterate over the ACK blocks and gaps
  for (uint32_t numAckBlockAnalyzed = 0; numAckBlockAnalyzed < ackBlockCount;
       ++numAckBlockAnalyzed, ++ack_it, ++gap_it)
    {
      for (auto sent_it = m_sentList.rbegin ();
           sent_it != m_sentList.rend () and !m_sentList.empty (); ++sent_it)                    // Visit sentList in reverse Order for optimization
        {
          NS_LOG_LOGIC (
            "Consider packet " << (*sent_it)->m_packetNumber << " (ACK block " << SequenceNumber32 ((*ack_it)) << ")");
          // The packet is in the next gap
          bool inGap = (gap_it < compGaps.end ())
            && ((*sent_it)->m_packetNumber
                <= SequenceNumber32 ((*gap_it)));
          if (inGap)               // Just for optimization we suppose All is perfectly ordered
            {
              NS_LOG_LOGIC (
                "Packet " << (*sent_it)->m_packetNumber << " missing");
              break;
            }
          // The packet is in the current block: ACK it
          NS_LOG_LOGIC ("Packet " << (*sent_it)->m_packetNumber << " ACKed");
          // the oldest range only reaches down to the ACK floor; older ranges may have been left out
          bool notInGap = (gap_it >= compGaps.end ())
            ? ((*sent_it)->m_packetNumber >= SequenceNumber32 (m_ackFloor))
            : ((*sent_it)->m_packetNumber > SequenceNumber32 ((*gap_it)));

          if ((*sent_it)->m_packetNumber <= SequenceNumber32 ((*ack_it))
              and notInGap and (*sent_it)->m_sacked == false)
            {
              (*sent_it)->m_sacked = true;
              m_inFlightValid = false;
              (*sent_it)->m_ackTime = Now ();
              newlyAcked.push_back ((*sent_it));
              UpdateRateSample ((*sent_it));
            }

        }
    }
  NS_LOG_LOGIC ("Mark lost packets");
  // Mark packets as lost as in RFC (Sec. 4.2.1 of draft-ietf-quic-recovery-15)
  Time newLossTime = Seconds (0);
  bool lost = false;
  bool outstanding = false;
  // Iterate over the sent packet list in reverse
  for (auto sent_it = m_sentList.rbegin ();
       sent_it != m_sentList.rend () and !m_sentList.empty ();
       ++sent_it)
    {
      // All previous packets are lost (skip retransmitted packets — give them time to be ACKed)
      if (lost)
        {
          if (!(*sent_it)->m_sacked)
            {
              (*sent_it)->m_lost = true;
              NS_LOG_LOGIC (
                "Packet " << (*sent_it)->m_packetNumber << " lost");
            }
        }
      else
        {
          // The packet is the last ACKed packet
          if ((*sent_it)->m_packetNumber.GetValue () == largestAcknowledged)
            {
              // Mark the packet as ACKed
              outstanding = true;
            }
          else if (outstanding && !(*sent_it)->m_sacked)
            {
              // ACK-based detection (RFC 9002 s6.1.1); each retransmission has its own
              // packet number, so retransmitted packets can be declared lost as well
              // RFC 9002 s6.1.1: lost when kPacketThreshold packets were sent after it and one of them was
              // acknowledged, i.e. LargestAck >= PacketNumber + kPacketThreshold (msquic waits for one more:
              // it is the same rule with kReorderingThreshold = 4)
              if (largestAcknowledged - (*sent_it)->m_packetNumber.GetValue ()
                     >= tcbd->m_kReorderingThreshold)
                {
                  (*sent_it)->m_lost = true;
                  lost = true;
                  NS_LOG_INFO (
                    "Largest ACK " << largestAcknowledged << ", lost packet " << (*sent_it)->m_packetNumber.GetValue () << " - reordering " << tcbd->m_kReorderingThreshold);
                }
              // Time-based detection (RFC 9002 s6.1.2)
              if (tcbd->m_kUsingTimeLossDetection && !(*sent_it)->m_lost)
                {
                  Time baseRtt = std::max (tcbd->m_smoothedRtt, tcbd->m_latestRtt);
                  Time lossDelay = std::max (baseRtt * tcbd->m_kTimeReorderingFraction,
                                             MilliSeconds (1));
                  Time deadline = (*sent_it)->m_lastSent + lossDelay;
                  if (Now () >= deadline)
                    {
                      (*sent_it)->m_lost = true;
                      lost = true;
                    }
                  else if (newLossTime == Seconds (0) || deadline < newLossTime)
                    {
                      newLossTime = deadline;
                    }
                }
            }
        }
    }
  tcbd->m_lossTime = newLossTime;

  // Clean up acked packets and return new ACKed packet vector
  CleanSentList ();
  return newlyAcked;
}

void QuicSocketTxBuffer::ResetSentList (uint32_t keepItems)
{
  NS_LOG_FUNCTION (this << keepItems);
  uint32_t kept = 0;
  for (auto sent_it = m_sentList.rbegin ();
       sent_it != m_sentList.rend () and !m_sentList.empty ();
       ++sent_it, kept++)
    {
      if (kept >= keepItems && !(*sent_it)->m_sacked)
        {
          (*sent_it)->m_lost = true;
        }
    }
}

std::vector<Ptr<QuicSocketTxItem> > QuicSocketTxBuffer::MarkOldestAsLost (uint32_t n)
{
  std::vector<Ptr<QuicSocketTxItem> > marked;
  for (auto &item : m_sentList)
    {
      if (marked.size () >= n)
        {
          break;
        }
      if (!item->m_sacked && !item->m_lost)
        {
          item->m_lost = true;
          marked.push_back (item);
        }
    }
  return marked;
}

bool QuicSocketTxBuffer::MarkAsLost (const SequenceNumber32 seq)
{
  NS_LOG_FUNCTION (this << seq);
  bool found = false;
  for (auto sent_it = m_sentList.begin ();
       sent_it != m_sentList.end () and !m_sentList.empty (); ++sent_it)
    {
      if ((*sent_it)->m_packetNumber == seq)
        {
          found = true;
          (*sent_it)->m_lost = true;
        }
    }
  return found;
}

uint32_t QuicSocketTxBuffer::Retransmission (SequenceNumber32 packetNumber)
{
  NS_LOG_FUNCTION (this);
  uint32_t toRetx = 0;
  // First pass: add lost packets to the application buffer
  for (auto sent_it = m_sentList.rbegin (); sent_it != m_sentList.rend ();
       ++sent_it)
    {
      Ptr<QuicSocketTxItem> item = *sent_it;
      if (item->m_lost)
        {
          if (!item->m_isStream0)
            {
              // A sent packet may carry several frames (e.g. from different streams, plus
              // ACKs). Re-queue each STREAM frame on its own so that the scheduler can
              // re-segment it; control frames such as ACK are not retransmitted.
              Ptr<Packet> pkt = item->m_packet->Copy ();
              while (pkt->GetSize () > 0)
                {
                  QuicSubheader sub;
                  pkt->RemoveHeader (sub);
                  uint64_t len = sub.GetLength ();
                  if (sub.IsStream () && len == 0)
                    {
                      len = pkt->GetSize ();
                    }
                  len = std::min<uint64_t> (len, pkt->GetSize ());
                  Ptr<Packet> data = CopyRange (pkt, 0, len);
                  pkt->RemoveAtStart (len);
                  // RFC 9000 s13.3: RESET_STREAM and STOP_SENDING are sent again until they are acknowledged
                  if (!sub.IsStream () && !sub.IsMaxData () && !sub.IsMaxStreamData ()
                      && !sub.IsRstStream () && !sub.IsStopSending ()
                      && !sub.IsBlocked () && !sub.IsStreamBlocked () && !sub.IsAckFrequency ()
                      && sub.GetFrameType () != QuicSubheader::MAX_STREAMS_BIDI && sub.GetFrameType () != QuicSubheader::MAX_STREAMS_UNI
                      && sub.GetFrameType () != QuicSubheader::STREAMS_BLOCKED_BIDI && sub.GetFrameType () != QuicSubheader::STREAMS_BLOCKED_UNI)
                    {
                      continue;
                    }
                  data->AddHeader (sub);
                  Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem> ();
                  retx->m_packetNumber = packetNumber++;
                  retx->m_isStream = true;
                  retx->m_isStream0 = false;
                  retx->m_packet = data;
                  retx->m_lost = false;
                  retx->m_retrans = true;
                  toRetx += data->GetSize ();
                  m_scheduler->Add (retx, true);
                }
              m_sentSize -= item->m_packet->GetSize ();
              continue;
            }
          Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem> ();
          retx->m_packetNumber = packetNumber++;
          retx->m_isStream = item->m_isStream;
          retx->m_isStream0 = item->m_isStream0;
          retx->m_packet = Create<Packet>();
          NS_LOG_INFO (
            "Retx packet " << item->m_packetNumber << " as " << retx->m_packetNumber.GetValue ());
          QuicSocketTxItem::MergeItems (*retx, *item);
          retx->m_lost = false;
          retx->m_retrans = true;
          toRetx += retx->m_packet->GetSize ();
          m_sentSize -= retx->m_packet->GetSize ();
          NS_LOG_INFO ("Lost stream 0 packet, re-inserting in list");
          m_streamZeroList.insert (m_streamZeroList.begin (), retx);
          m_streamZeroSize += retx->m_packet->GetSize ();
          m_numFrameStream0InBuffer++;
        }
    }

  NS_LOG_LOGIC ("Remove retransmitted packets from sent list");
  auto sent_it = m_sentList.begin ();
  // Remove lost packets from the sent list
  while (!m_sentList.empty () && sent_it != m_sentList.end ())
    {
      Ptr<QuicSocketTxItem> item = *sent_it;
      if (item->m_lost)
        {
          // Remove lost packet from sent vector
          sent_it = m_sentList.erase (sent_it);
          m_inFlightValid = false;
        }
      else
        {
          sent_it++;
        }
    }
  return toRetx;
}

void QuicSocketTxBuffer::DetectTimeLoss (Ptr<TcpSocketState> tcb, uint32_t largestAcknowledged)
{
  NS_LOG_FUNCTION (this << largestAcknowledged);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  Time baseRtt = std::max (tcbd->m_smoothedRtt, tcbd->m_latestRtt);
  Time lossDelay = std::max (baseRtt * tcbd->m_kTimeReorderingFraction, MilliSeconds (1));
  Time newLossTime = Seconds (0);
  for (auto &item : m_sentList)
    {
      if (item->m_sacked || item->m_lost || item->m_packetNumber.GetValue () >= largestAcknowledged)
        {
          continue;
        }
      Time deadline = item->m_lastSent + lossDelay;
      if (Now () >= deadline)
        {
          item->m_lost = true;
        }
      else if (newLossTime == Seconds (0) || deadline < newLossTime)
        {
          newLossTime = deadline;
        }
    }
  tcbd->m_lossTime = newLossTime;
}

std::vector<Ptr<QuicSocketTxItem> > QuicSocketTxBuffer::DetectLostPackets ()
{
  NS_LOG_FUNCTION (this);
  std::vector<Ptr<QuicSocketTxItem> > lost;

  for (auto sent_it = m_sentList.begin ();
       sent_it != m_sentList.end () and !m_sentList.empty (); ++sent_it)
    {
      if ((*sent_it)->m_lost)
        {
          lost.push_back ((*sent_it));
          NS_LOG_INFO ("Packet " << (*sent_it)->m_packetNumber << " is lost");
        }
    }
  return lost;
}

bool QuicSocketTxBuffer::HasAckedPacketBetween (Time tOldest, Time tNewest)
{
  // RFC 9002 §7.6.2: check if any acknowledged packet was sent strictly between
  // the oldest and newest lost packet send times (would invalidate persistent congestion).
  for (auto &item : m_sentList)
    {
      if (item->m_sacked && item->m_lastSent > tOldest && item->m_lastSent < tNewest)
        {
          return true;
        }
    }
  return false;
}

uint32_t QuicSocketTxBuffer::GetLost ()
{
  NS_LOG_FUNCTION (this);
  uint32_t lostCount = 0;
  for (auto sent_it = m_sentList.begin ();
       sent_it != m_sentList.end () and !m_sentList.empty (); ++sent_it)
    {
      if ((*sent_it)->m_lost)
        {
          lostCount += (*sent_it)->m_packet->GetSize ();
        }
    }
  return lostCount;
}

void QuicSocketTxBuffer::CleanSentList ()
{
  NS_LOG_FUNCTION (this);
  auto sent_it = m_sentList.begin ();
  // All packets up to here are ACKed (already sent to the receiver app)
  while (!m_sentList.empty () && (*sent_it)->m_sacked && !(*sent_it)->m_lost)
    {
      // Remove ACKed packet from sent vector
      Ptr<QuicSocketTxItem> item = *sent_it;
      item->m_acked = true;
      m_sentSize -= item->m_packet->GetSize ();
      NS_LOG_LOGIC (
        "Packet " << item->m_packetNumber << " received and ACKed. Removing from sent buffer");
      m_sentList.erase (sent_it);
      m_inFlightValid = false;
      sent_it = m_sentList.begin ();
    }
}

uint32_t QuicSocketTxBuffer::Available (void) const
{
  return m_maxBuffer - m_streamZeroSize - m_scheduler->AppSize ();
}

uint32_t QuicSocketTxBuffer::GetMaxBufferSize (void) const
{
  return m_maxBuffer;
}

void QuicSocketTxBuffer::SetMaxBufferSize (uint32_t n)
{
  m_maxBuffer = n;
}

uint32_t QuicSocketTxBuffer::AppSize (void) const
{
  return m_streamZeroSize + m_scheduler->AppSize ();
}

uint32_t QuicSocketTxBuffer::GetNumFrameStream0InBuffer (void) const
{
  return m_numFrameStream0InBuffer;
}

uint32_t QuicSocketTxBuffer::BytesInFlight () const
{
  // the sum over the sent list only changes when packets are added, acknowledged or removed, and it
  // is asked for several times per packet: keep it until one of those happens
  if (m_inFlightValid)
    {
      return m_inFlightCache;
    }
  uint32_t inFlight = 0;
  bool unacked = false;
  for (const auto &item : m_sentList)
    {
      if (item->m_sacked)
        {
          continue;
        }
      unacked = true;
      if (!item->m_isStream0 && item->m_isStream)
        {
          inFlight += item->m_packet->GetSize ();
        }
    }
  m_inFlightCache = inFlight;
  m_hasUnacked = unacked;
  m_inFlightValid = true;
  return inFlight;
}

bool QuicSocketTxBuffer::HasUnackedPackets () const
{
  BytesInFlight ();
  return m_hasUnacked;
}

void QuicSocketTxBuffer::SetQuicSocketState (Ptr<QuicSocketState> tcb)
{
  NS_LOG_FUNCTION (this);
  m_tcb = tcb;
}

void QuicSocketTxBuffer::SetScheduler (Ptr<QuicSocketTxScheduler> sched)
{
  NS_LOG_FUNCTION (this);
  m_scheduler = sched;
}

void QuicSocketTxBuffer::UpdatePacketSent (SequenceNumber32 seq, uint32_t sz)
{
  NS_LOG_FUNCTION (this << seq << sz);

  if (m_tcb == nullptr or sz == 0)
    {
      return;
    }

  if (m_tcb->m_bytesInFlight.Get () == 0)
    {
      m_tcb->m_firstSentTime = Simulator::Now ();
      m_tcb->m_deliveredTime = Simulator::Now ();
    }

  Ptr<QuicSocketTxItem> item = nullptr;
  for (auto it = m_sentList.rbegin (); it != m_sentList.rend (); ++it)
    {
      if ((*it)->m_packetNumber == seq)
        {
          item = *it;
          break;
        }
    }
  NS_ASSERT_MSG (item != nullptr, "not found seq " << seq);
  item->m_firstSentTime = m_tcb->m_firstSentTime;
  item->m_deliveredTime = m_tcb->m_deliveredTime;
  item->m_isAppLimited = (m_tcb->m_appLimitedUntil > m_tcb->m_delivered);
  item->m_delivered = m_tcb->m_delivered;
  item->m_ackBytesSent = m_tcb->m_ackBytesSent;
}

void
QuicSocketTxBuffer::UpdateAckSent (SequenceNumber32 seq, uint32_t sz)
{
  if (m_tcb == nullptr or sz == 0)
    {
      return;
    }

  m_tcb->m_ackBytesSent += sz;
}

struct RateSample*
QuicSocketTxBuffer::GetRateSample ()
{
  NS_LOG_FUNCTION (this);
  return &m_rs;
}

void
QuicSocketTxBuffer::UpdateRateSample (Ptr<QuicSocketTxItem> item)
{
  NS_LOG_FUNCTION (this << item);

  if (m_tcb == nullptr or item->m_deliveredTime == Time::Max ())
    {
      // item already SACKed
      return;
    }

  m_tcb->m_delivered         += item->m_packet->GetSize ();
  m_tcb->m_deliveredTime      = Simulator::Now ();

  if (item->m_delivered > m_rs.m_priorDelivered)
    {
      m_rs.m_priorDelivered   = item->m_delivered;
      m_rs.m_priorTime        = item->m_deliveredTime;
      m_rs.m_isAppLimited     = item->m_isAppLimited;
      m_rs.m_sendElapsed      = item->m_lastSent - item->m_firstSentTime;
      m_rs.m_ackElapsed       = m_tcb->m_deliveredTime - item->m_deliveredTime;
      m_tcb->m_firstSentTime  = item->m_lastSent;
      m_rs.m_priorAckBytesSent  = item->m_ackBytesSent;
    }

  /* Mark the packet as delivered once it is SACKed to avoid
   * being used again when it's cumulatively acked.
   */
  item->m_deliveredTime = Time::Max ();
  m_tcb->m_txItemDelivered = item->m_delivered;
}

bool
QuicSocketTxBuffer::GenerateRateSample ()
{
  NS_LOG_FUNCTION (this);

  if (m_tcb == nullptr)
    {
      return false;
    }

  if (m_rs.m_priorTime == Seconds (0))
    {
      return false;
    }

  m_rs.m_interval = std::max (m_rs.m_sendElapsed, m_rs.m_ackElapsed);

  m_rs.m_delivered = m_tcb->m_delivered - m_rs.m_priorDelivered;


  if (m_rs.m_ackBytesSent < m_tcb->m_ackBytesSent - m_rs.m_priorAckBytesSent or++ m_rs.m_ackBytesMaxWin > 5) //quick maxfilter implementation
    {
      m_rs.m_ackBytesSent = m_tcb->m_ackBytesSent - m_rs.m_priorAckBytesSent;
      m_rs.m_ackBytesMaxWin = 0;
    }

  uint32_t discountedDelivered = m_rs.m_delivered > m_rs.m_ackBytesSent ? m_rs.m_delivered - m_rs.m_ackBytesSent : 0U;

  if (m_rs.m_interval < m_tcb->m_minRtt)
    {
      m_rs.m_interval = Seconds (0);
      return false;
    }

  if (m_rs.m_interval != Seconds (0))
    {
      m_rs.m_deliveryRate = DataRate (discountedDelivered * 8.0 / m_rs.m_interval.GetSeconds ());
    }
  NS_LOG_DEBUG ("computed delivery rate: " << m_rs.m_deliveryRate);
  return true;
}


void QuicSocketTxBuffer::SetLatency (uint32_t streamId, Time latency)
{
  // Only relevant for the EDF scheduler
  if (m_scheduler->GetTypeId () == QuicSocketTxEdfScheduler::GetTypeId ())
    {
      (DynamicCast<QuicSocketTxEdfScheduler> (m_scheduler))->SetLatency (streamId, latency);
    }
}

Time QuicSocketTxBuffer::GetLatency (uint32_t streamId)
{
  // Only relevant for the EDF scheduler
  if (m_scheduler->GetTypeId () == QuicSocketTxEdfScheduler::GetTypeId ())
    {
      return (DynamicCast<QuicSocketTxEdfScheduler> (m_scheduler))->GetLatency (streamId);
    }
  else
    {
      return Seconds (0);
    }
}

void QuicSocketTxBuffer::SetDefaultLatency (Time latency)
{
  // Only relevant for the EDF scheduler
  if (m_scheduler->GetTypeId () == QuicSocketTxEdfScheduler::GetTypeId ())
    {
      (DynamicCast<QuicSocketTxEdfScheduler> (m_scheduler))->SetDefaultLatency (latency);
    }
}

Time QuicSocketTxBuffer::GetDefaultLatency ()
{
  return GetLatency (0);
}

}
