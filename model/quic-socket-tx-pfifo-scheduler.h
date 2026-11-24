/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#ifndef QUICSOCKETTXPFIFOSCHEDULER_H
#define QUICSOCKETTXPFIFOSCHEDULER_H

#include "quic-socket-tx-scheduler.h"

#include <queue>
#include <vector>

namespace ns3
{

/**
 * \brief The PFIFO implementation
 *
 * This class is a Priority FIFO implementation of the socket scheduler, which prioritizes streams
 * with a lower stream number
 */
class QuicSocketTxPFifoScheduler : public QuicSocketTxScheduler
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    QuicSocketTxPFifoScheduler();
    QuicSocketTxPFifoScheduler(const QuicSocketTxPFifoScheduler& other);
    virtual ~QuicSocketTxPFifoScheduler(void);

    /**
     * Add a tx item to the scheduling list and assign priority
     *
     * \param item a smart pointer to a transmission item
     * \param retx true if the transmission item is being retransmitted
     *
     */
    void Add(Ptr<QuicSocketTxItem> item, bool retx) override;

  private:
    bool m_retxFirst;
};

} // namespace ns3

#endif /* QUIC_SOCKET_TX_PFIFO_SCHEDULER_H */
