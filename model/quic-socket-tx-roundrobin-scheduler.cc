/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "quic-socket-tx-roundrobin-scheduler.h"

#include <cmath>
#include "ns3/log.h"
#include "quic-subheader.h"
#include "quic-socket-tx-buffer.h"
#include "quic-socket-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketTxRoundRobinScheduler");

NS_OBJECT_ENSURE_REGISTERED (QuicSocketTxRoundRobinScheduler);

TypeId
QuicSocketTxRoundRobinScheduler::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketTxRoundRobinScheduler")
    .SetParent<QuicSocketTxStreamFifoScheduler> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketTxRoundRobinScheduler> ()
  ;
  return tid;
}

QuicSocketTxRoundRobinScheduler::QuicSocketTxRoundRobinScheduler ()
  : QuicSocketTxStreamFifoScheduler ()
{
}

QuicSocketTxRoundRobinScheduler::QuicSocketTxRoundRobinScheduler (const QuicSocketTxRoundRobinScheduler &other)
  : QuicSocketTxStreamFifoScheduler (other), m_cumulative (other.m_cumulative), m_round (other.m_round)
{
}

QuicSocketTxRoundRobinScheduler::~QuicSocketTxRoundRobinScheduler (void)
{
}

void
QuicSocketTxRoundRobinScheduler::Add (Ptr<QuicSocketTxItem> item, bool retx)
{
  QuicSubheader qsb;
  item->m_packet->PeekHeader (qsb);
  uint64_t id = qsb.GetStreamId ();
  double priority = -1;   // retransmissions go first
  if (!retx)
    {
      StreamState &st = m_streams[id];
      bool idle = st.queued == 0 && !st.backlogged;
      if (idle)
        {
          st.rank = m_nextRank;
          m_nextRank += 1.0;
          // an idle stream starts at the current round instead of collecting credit
          m_cumulative[id] = std::max (m_cumulative[id], m_round * kRoundBytes);
        }
      double &cum = m_cumulative[id];
      double round = std::floor (cum / kRoundBytes);
      cum += item->m_packet->GetSize ();
      // lower value goes first: stream priority, then the round, then the order of arrival in it
      priority = (65535 - st.priority) * 1e12 + round * 1e6 + st.rank;
    }
  AddScheduleItem (CreateObject<QuicSocketTxScheduleItem> (id, qsb.GetOffset (), priority, item), retx);
}

void
QuicSocketTxRoundRobinScheduler::OnItemServed (double priority)
{
  if (priority < 0)
    {
      return;
    }
  double round = std::floor (std::fmod (priority, 1e12) / 1e6);
  m_round = std::max (m_round, round);
}

} // namespace ns3
