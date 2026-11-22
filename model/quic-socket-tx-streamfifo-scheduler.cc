/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "quic-socket-tx-streamfifo-scheduler.h"

#include "ns3/log.h"
#include "quic-subheader.h"
#include "quic-socket-tx-buffer.h"
#include "quic-socket-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketTxStreamFifoScheduler");

NS_OBJECT_ENSURE_REGISTERED (QuicSocketTxStreamFifoScheduler);

TypeId
QuicSocketTxStreamFifoScheduler::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketTxStreamFifoScheduler")
    .SetParent<QuicSocketTxScheduler> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketTxStreamFifoScheduler> ()
  ;
  return tid;
}

QuicSocketTxStreamFifoScheduler::QuicSocketTxStreamFifoScheduler ()
  : QuicSocketTxScheduler ()
{
}

QuicSocketTxStreamFifoScheduler::QuicSocketTxStreamFifoScheduler (const QuicSocketTxStreamFifoScheduler &other)
  : QuicSocketTxScheduler (other), m_streams (other.m_streams), m_nextRank (other.m_nextRank)
{
}

QuicSocketTxStreamFifoScheduler::~QuicSocketTxStreamFifoScheduler (void)
{
}

void
QuicSocketTxStreamFifoScheduler::Add (Ptr<QuicSocketTxItem> item, bool retx)
{
  QuicSubheader qsb;
  item->m_packet->PeekHeader (qsb);
  uint64_t id = qsb.GetStreamId ();
  double priority = -1;   // retransmissions go first
  if (!retx)
    {
      StreamState &st = m_streams[id];
      if (st.queued == 0 && !st.backlogged)
        {
          st.rank = m_nextRank;
          m_nextRank += 1.0;
        }
      // lower value is served first: higher msquic priority, then older backlog
      priority = (65535 - st.priority) * 1e9 + st.rank;
    }
  AddScheduleItem (CreateObject<QuicSocketTxScheduleItem> (id, qsb.GetOffset (), priority, item), retx);
}

void
QuicSocketTxStreamFifoScheduler::SetStreamPriority (uint64_t streamId, uint16_t priority)
{
  m_streams[streamId].priority = priority;
}

void
QuicSocketTxStreamFifoScheduler::OnStreamBacklog (uint64_t streamId, bool backlogged)
{
  StreamState &st = m_streams[streamId];
  if (backlogged && !st.backlogged && st.queued == 0)
    {
      st.rank = m_nextRank;
      m_nextRank += 1.0;
    }
  st.backlogged = backlogged;
}

void
QuicSocketTxStreamFifoScheduler::OnQueued (uint64_t streamId, uint32_t bytes)
{
  m_streams[streamId].queued += bytes;
}

void
QuicSocketTxStreamFifoScheduler::OnDequeued (uint64_t streamId, uint32_t bytes)
{
  StreamState &st = m_streams[streamId];
  st.queued = (bytes >= st.queued) ? 0 : st.queued - bytes;
}

} // namespace ns3
