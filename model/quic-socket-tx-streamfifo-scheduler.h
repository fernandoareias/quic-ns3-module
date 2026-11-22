/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef QUIC_SOCKET_TX_STREAMFIFO_SCHEDULER_H
#define QUIC_SOCKET_TX_STREAMFIFO_SCHEDULER_H

#include "quic-socket-tx-scheduler.h"
#include <map>

namespace ns3 {

/**
 * \brief Per-stream FIFO, as msquic's default stream scheduling
 *
 * Streams are served in the order in which they became backlogged; a stream keeps its place in
 * the queue (and is drained before the next one) as long as it has data queued, even if the
 * data was written after the other streams'.
 */
class QuicSocketTxStreamFifoScheduler : public QuicSocketTxScheduler
{
public:
  static TypeId GetTypeId (void);

  QuicSocketTxStreamFifoScheduler ();
  QuicSocketTxStreamFifoScheduler (const QuicSocketTxStreamFifoScheduler &other);
  virtual ~QuicSocketTxStreamFifoScheduler (void);

  void Add (Ptr<QuicSocketTxItem> item, bool retx) override;

  void SetStreamPriority (uint64_t streamId, uint16_t priority) override;

  void OnStreamBacklog (uint64_t streamId, bool backlogged) override;

protected:
  void OnQueued (uint64_t streamId, uint32_t bytes) override;
  void OnDequeued (uint64_t streamId, uint32_t bytes) override;

protected:
  struct StreamState
  {
    double rank {0};
    uint64_t queued {0};
    uint16_t priority {0x7FFF};
    bool backlogged {false};   //!< unsent data still sits in the stream buffer
  };
  std::map<uint64_t, StreamState> m_streams;
  double m_nextRank {1.0};
};

} // namespace ns3

#endif
