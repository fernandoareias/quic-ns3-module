/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef QUIC_SOCKET_TX_ROUNDROBIN_SCHEDULER_H
#define QUIC_SOCKET_TX_ROUNDROBIN_SCHEDULER_H

#include "quic-socket-tx-streamfifo-scheduler.h"

namespace ns3 {

/**
 * \brief Round-robin stream scheduling (msquic QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN)
 *
 * Streams of the same priority take turns: a stream sends QUIC_STREAM_SEND_BATCH_COUNT (8) packets
 * and goes to the back of the line. A stream that was idle does not collect credit for the time it
 * had nothing to send.
 */
class QuicSocketTxRoundRobinScheduler : public QuicSocketTxStreamFifoScheduler
{
public:
  static TypeId GetTypeId (void);

  QuicSocketTxRoundRobinScheduler ();
  QuicSocketTxRoundRobinScheduler (const QuicSocketTxRoundRobinScheduler &other);
  virtual ~QuicSocketTxRoundRobinScheduler (void);

  void Add (Ptr<QuicSocketTxItem> item, bool retx) override;

protected:
  void OnItemServed (double priority) override;

private:
  static constexpr double kRoundBytes = 8 * 1460;   //!< one turn of a stream: 8 packets
  std::map<uint64_t, double> m_cumulative;          //!< bytes queued per stream since it became active
  double m_round {0};                               //!< round of the last item served
};

} // namespace ns3

#endif
