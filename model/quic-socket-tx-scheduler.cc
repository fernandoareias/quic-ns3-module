/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#include "quic-socket-tx-scheduler.h"

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
#include "quic-socket-tx-buffer.h"
#include "quic-socket-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketTxScheduler");

NS_OBJECT_ENSURE_REGISTERED (QuicSocketTxScheduler);
NS_OBJECT_ENSURE_REGISTERED (QuicSocketTxScheduleItem);

TypeId
QuicSocketTxScheduleItem::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketTxScheduleItem")
    .SetParent<Object> ()
    .SetGroupName ("Internet")
  ;
  return tid;
}

int
QuicSocketTxScheduleItem::Compare (const QuicSocketTxScheduleItem & o) const
{
  if (m_priority != o.m_priority)
    {
      return (m_priority < o.m_priority) ? -1 : 1;
    }
  if (m_streamId != o.m_streamId)
    {
      return (m_streamId < o.m_streamId) ? -1 : 1;
    }
  if (m_offset != o.m_offset)
    {
      return (m_offset < o.m_offset) ? -1 : 1;
    }

  return 0;
}



QuicSocketTxScheduleItem::QuicSocketTxScheduleItem (uint64_t id, uint64_t off, double p, Ptr<QuicSocketTxItem> it)
  : m_streamId (id), 
    m_offset (off), 
    m_priority (p), 
    m_item (it)
{}

QuicSocketTxScheduleItem::QuicSocketTxScheduleItem (const QuicSocketTxScheduleItem &other)
  : m_streamId (other.m_streamId), 
    m_offset (other.m_offset), 
    m_priority (other.m_priority)
{
  m_item = CreateObject<QuicSocketTxItem> (*(other.m_item));
}


Ptr<QuicSocketTxItem>
QuicSocketTxScheduleItem::GetItem () const
{
  return m_item;
}

uint64_t
QuicSocketTxScheduleItem::GetStreamId () const
{
  return m_streamId;
}


uint64_t
QuicSocketTxScheduleItem::GetOffset () const
{
  return m_offset;
}

double
QuicSocketTxScheduleItem::GetPriority () const
{
  return m_priority;
}

void
QuicSocketTxScheduleItem::SetPriority (double priority)
{
  m_priority = priority;
}



TypeId
QuicSocketTxScheduler::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketTxScheduler")
    .SetParent<Object> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketTxScheduler> ()
  ;
  return tid;
}

QuicSocketTxScheduler::QuicSocketTxScheduler () : m_appSize (0)
{
  m_appList = QuicTxPacketList ();
}

QuicSocketTxScheduler::QuicSocketTxScheduler (const QuicSocketTxScheduler &other) : m_appSize (other.m_appSize)
{
  m_appList = other.m_appList;
}

QuicSocketTxScheduler::~QuicSocketTxScheduler (void)
{
  m_appList = QuicTxPacketList ();
  m_appSize = 0;
}


void
QuicSocketTxScheduler::Add (Ptr<QuicSocketTxItem> item, bool retx)
{
  NS_LOG_FUNCTION (this << item);
  QuicSubheader qsb;
  item->m_packet->PeekHeader (qsb);
  double priority = -1;
  NS_LOG_INFO ("Adding packet on stream " << qsb.GetStreamId ());
  if (!retx)
    {
      NS_LOG_INFO ("Standard item, add at end (offset " << qsb.GetOffset () << ")");
      priority = Simulator::Now ().GetSeconds ();
    }
  else
    {
      NS_LOG_INFO ("Retransmitted item, add at beginning (offset " << qsb.GetOffset () << ")");
    }
  Ptr<QuicSocketTxScheduleItem> sched = CreateObject<QuicSocketTxScheduleItem> (qsb.GetStreamId (), qsb.GetOffset (), priority, item);
  AddScheduleItem (sched, retx);
}


void
QuicSocketTxScheduler::AddScheduleItem (Ptr<QuicSocketTxScheduleItem> item, bool retx)
{
  NS_LOG_FUNCTION (this << item);
  m_appList.push (item);
  m_appSize += item->GetItem ()->m_packet->GetSize ();
  OnQueued (item->GetStreamId (), item->GetItem ()->m_packet->GetSize ());
  QuicSubheader qsb;
  item->GetItem ()->m_packet->PeekHeader (qsb);
  NS_LOG_INFO ("Adding packet on stream " << qsb.GetStreamId () << " with priority " << item->GetPriority ());
  if (!retx)
    {
      NS_LOG_INFO ("Standard item, add at end (offset " << qsb.GetOffset () << ")");
    }
  else
    {
      NS_LOG_INFO ("Retransmitted item, add at beginning (offset " << qsb.GetOffset () << ")");
    }
}

void
QuicSocketTxScheduler::SetStreamPriority (uint64_t streamId, uint16_t priority)
{
}

void
QuicSocketTxScheduler::OnStreamBacklog (uint64_t streamId, bool backlogged)
{
}

void
QuicSocketTxScheduler::OnItemServed (double priority)
{
}

void
QuicSocketTxScheduler::OnQueued (uint64_t streamId, uint32_t bytes)
{
}

void
QuicSocketTxScheduler::OnDequeued (uint64_t streamId, uint32_t bytes)
{
}

Ptr<QuicSocketTxItem>
QuicSocketTxScheduler::GetNewSegment (uint32_t numBytes)
{
  NS_LOG_FUNCTION (this << numBytes);

  bool firstSegment = true;
  Ptr<Packet> currentPacket = 0;
  Ptr<QuicSocketTxItem> currentItem = 0;
  Ptr<QuicSocketTxItem> outItem = CreateObject<QuicSocketTxItem>();
  outItem->m_isStream = true;   // Packets sent with this method are always stream packets
  outItem->m_isStream0 = false;
  outItem->m_packet = Create<Packet> ();
  uint32_t outItemSize = 0;


  while (m_appSize > 0 && outItemSize < numBytes)
    {
      Ptr<QuicSocketTxScheduleItem> scheduleItem = m_appList.top ();
      currentItem = scheduleItem->GetItem ();
      currentPacket = currentItem->m_packet;
      m_appSize -= currentPacket->GetSize ();
      m_appList.pop ();
      OnDequeued (scheduleItem->GetStreamId (), currentPacket->GetSize ());
      OnItemServed (scheduleItem->GetPriority ());

      if (outItemSize + currentItem->m_packet->GetSize ()   /*- subheaderSize*/
          <= numBytes)       // Merge
        {
          NS_LOG_LOGIC ("Add complete frame to the outItem - size "
                        << currentItem->m_packet->GetSize ()
                        << " m_appSize " << m_appSize);
          QuicSubheader qsb;
          currentPacket->PeekHeader (qsb);
          NS_LOG_INFO ("Packet: stream " << qsb.GetStreamId () << ", offset " << qsb.GetOffset ());
          QuicSocketTxItem::MergeItems (*outItem, *currentItem);
          outItemSize += currentItem->m_packet->GetSize ();

          NS_LOG_LOGIC ("Updating application buffer size: " << m_appSize);
          continue;
        }
      else if (firstSegment)  // we cannot transmit a full packet, so let's split it and update the subheaders
        {
          firstSegment = false;

          // get the currentPacket subheader
          QuicSubheader qsb;
          currentPacket->PeekHeader (qsb);

          // new packet size
          // The header of the part sent now always carries a LENGTH field, so size it from that header
          // (the stored one may lack the bit) and not from the header of the frame being split
          bool offBit = (qsb.GetOffset () != 0);
          auto headerSize = [&] (uint32_t len)
          {
            return (int) QuicSubheader::CreateStreamSubHeader (qsb.GetStreamId (), qsb.GetOffset (), len, offBit, true, false).GetSerializedSize ();
          };
          int room = (int)numBytes - (int)outItemSize;
          int newPacketSizeInt = room - headerSize (std::max (room, 0));
          if (newPacketSizeInt > 0)
            {
              int refined = room - headerSize (newPacketSizeInt);
              if (refined > newPacketSizeInt && headerSize (refined) == headerSize (newPacketSizeInt))
                {
                  newPacketSizeInt = refined;
                }
            }
          if (newPacketSizeInt <= 0)
            {
              NS_LOG_INFO ("Not enough bytes even for the header");
              m_appList.push (scheduleItem);
              m_appSize += currentPacket->GetSize ();
              OnQueued (scheduleItem->GetStreamId (), currentPacket->GetSize ());
              break;
            }
          else
            {
              NS_LOG_INFO ("Split packet on stream " << qsb.GetStreamId () << ", sending " << newPacketSizeInt << " bytes from offset " << qsb.GetOffset ());

              currentPacket->RemoveHeader (qsb);
              uint32_t newPacketSize = (uint32_t)newPacketSizeInt;

              NS_LOG_LOGIC ("Add incomplete frame to the outItem");
              uint32_t totPacketSize = currentItem->m_packet->GetSize ();
              NS_LOG_LOGIC ("Extracted " << outItemSize << " bytes");

              uint32_t oldOffset = qsb.GetOffset ();
              uint32_t newOffset = oldOffset + newPacketSize;
              bool oldOffBit = !(oldOffset == 0);
              bool newOffBit = true;
              uint32_t oldLength = qsb.GetLength ();
              uint32_t newLength = 0;
              bool newLengthBit = true;
              newLength = totPacketSize - newPacketSize;
              if (oldLength == 0)
                {
                  newLengthBit = false;
                }
              bool lengthBit = true;
              bool oldFinBit = qsb.IsStreamFin ();
              bool newFinBit = false;

              QuicSubheader newQsbToTx = QuicSubheader::CreateStreamSubHeader (qsb.GetStreamId (),
                                                                               oldOffset, newPacketSize, oldOffBit, lengthBit, newFinBit);
              QuicSubheader newQsbToBuffer = QuicSubheader::CreateStreamSubHeader (qsb.GetStreamId (),
                                                                                   newOffset, newLength, newOffBit, newLengthBit, oldFinBit);

              Ptr<Packet> firstPartPacket = CopyRange (currentItem->m_packet,
                0, newPacketSize);
              NS_ASSERT_MSG (firstPartPacket->GetSize () == newPacketSize,
                             "Wrong size " << firstPartPacket->GetSize ());
              firstPartPacket->AddHeader (newQsbToTx);

              NS_LOG_INFO ("Split packet, putting second part back in application buffer - stream " << newQsbToBuffer.GetStreamId () << ", storing from offset " << newQsbToBuffer.GetOffset ());


              Ptr<Packet> secondPartPacket = CopyRange (currentItem->m_packet,
                newPacketSize, newLength);
              secondPartPacket->AddHeader (newQsbToBuffer);

              Ptr<QuicSocketTxItem> toBeBuffered = CreateObject<QuicSocketTxItem> (*currentItem);
              toBeBuffered->m_packet = secondPartPacket;
              currentItem->m_packet = firstPartPacket;

              QuicSocketTxItem::MergeItems (*outItem, *currentItem);
              outItemSize += currentItem->m_packet->GetSize ();

              m_appList.push (CreateObject<QuicSocketTxScheduleItem> (scheduleItem->GetStreamId (), scheduleItem->GetOffset (), scheduleItem->GetPriority (), toBeBuffered));
              m_appSize += toBeBuffered->m_packet->GetSize ();
              OnQueued (scheduleItem->GetStreamId (), toBeBuffered->m_packet->GetSize ());


              NS_LOG_LOGIC ("Buffer size: " << m_appSize << " (put back " << toBeBuffered->m_packet->GetSize () << " bytes)");
              break; // at most one segment
            }
        }
    }

  NS_LOG_INFO ("Update: remaining App Size " << m_appSize << ", object size " << outItemSize);

  //Print(std::cout);

  return outItem;
}

uint32_t
QuicSocketTxScheduler::AppSize (void) const
{
  return m_appSize;
}


}
