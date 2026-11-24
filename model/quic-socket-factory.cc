/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 */

#include "quic-socket-factory.h"

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/socket.h"

namespace ns3
{
NS_LOG_COMPONENT_DEFINE("QuicSocketFactory");

NS_OBJECT_ENSURE_REGISTERED(QuicSocketFactory);

TypeId
QuicSocketFactory::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicSocketFactory")
                            .SetParent<SocketFactory>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicSocketFactory>();
    return tid;
}

QuicSocketFactory::QuicSocketFactory()
    : m_quicl4(0)
{
    NS_LOG_INFO("Creating QuicSocketFactory");
    m_sockets = std::vector<Ptr<QuicSocketBase>>();
}

QuicSocketFactory::~QuicSocketFactory()
{
    NS_LOG_INFO("Destroying QuicSocketFactory");
    NS_ASSERT(m_quicl4 == nullptr);
}

void
QuicSocketFactory::SetQuicL4(Ptr<QuicL4Protocol> quic)
{
    m_quicl4 = quic;
}

Ptr<Socket>
QuicSocketFactory::CreateSocket(void)
{
    NS_LOG_INFO("QuicSocketFactory -- creating socket");
    return m_quicl4->CreateSocket();
}

void
QuicSocketFactory::DoDispose(void)
{
    m_quicl4 = 0;
    SocketFactory::DoDispose();
}

} // namespace ns3
