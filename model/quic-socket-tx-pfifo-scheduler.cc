/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#include "quic-socket-tx-pfifo-scheduler.h"

#include "quic-socket-base.h"
#include "quic-subheader.h"

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicSocketTxPFifoScheduler");

NS_OBJECT_ENSURE_REGISTERED(QuicSocketTxPFifoScheduler);

TypeId
QuicSocketTxPFifoScheduler::GetTypeId(void)
{
    static TypeId tid =
        TypeId("ns3::QuicSocketTxPFifoScheduler")
            .SetParent<QuicSocketTxScheduler>()
            .SetGroupName("Internet")
            .AddConstructor<QuicSocketTxPFifoScheduler>()
            .AddAttribute("RetxFirst",
                          "Prioritize retransmissions regardless of stream",
                          BooleanValue(false),
                          MakeBooleanAccessor(&QuicSocketTxPFifoScheduler::m_retxFirst),
                          MakeBooleanChecker());
    return tid;
}

QuicSocketTxPFifoScheduler::QuicSocketTxPFifoScheduler()
    : QuicSocketTxScheduler(),
      m_retxFirst(false)
{
}

QuicSocketTxPFifoScheduler::QuicSocketTxPFifoScheduler(const QuicSocketTxPFifoScheduler& other)
    : QuicSocketTxScheduler(other),
      m_retxFirst(other.m_retxFirst)
{
}

QuicSocketTxPFifoScheduler::~QuicSocketTxPFifoScheduler(void)
{
}

void
QuicSocketTxPFifoScheduler::Add(Ptr<QuicSocketTxItem> item, bool retx)
{
    NS_LOG_FUNCTION(this << item);
    QuicSubheader qsb;
    item->m_packet->PeekHeader(qsb);
    NS_LOG_INFO("Adding packet on stream " << qsb.GetStreamId());
    if (!retx)
    {
        NS_LOG_INFO("Standard item, add at end (offset " << qsb.GetOffset() << ")");
    }
    else
    {
        NS_LOG_INFO("Retransmitted item, add at beginning (offset " << qsb.GetOffset() << ")");
    }
    AddScheduleItem(
        CreateObject<QuicSocketTxScheduleItem>(qsb.GetStreamId(), qsb.GetOffset(), 0, item),
        (retx && m_retxFirst));
}

} // namespace ns3
