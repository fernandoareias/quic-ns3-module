/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_INJECTION_H
#define QUIC_INJECTION_H

/**
 * @file
 * Test helpers that put chosen frames in a packet of a live connection: the receive error model of
 * a device rewrites the frames of one packet on its way to the node, and the scenario is two nodes
 * on a link that set up a connection and write ten bytes once it is open.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-header.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-subheader.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <vector>

namespace quic_test
{

using namespace ns3;

/**
 * Replaces the frames of the first QUIC short header packet that is sent to a node, once armed and
 * when that packet starts with a STREAM frame. The packet keeps its headers and its size: the
 * frames given are followed by zero bytes (PADDING).
 */
class PayloadInjector : public ErrorModel
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::QuicFramePayloadInjector")
                                .SetParent<ErrorModel>()
                                .AddConstructor<PayloadInjector>();
        return tid;
    }

    void Configure(Ipv4Address dst, std::vector<uint8_t> frames)
    {
        m_dst = dst;
        m_frames = std::move(frames);
    }

    void Arm(void)
    {
        m_armed = true;
    }

    bool Injected(void) const
    {
        return m_injected;
    }

  private:
    bool DoCorrupt(Ptr<Packet> p) override
    {
        if (!m_armed || m_injected)
        {
            return false;
        }
        Ptr<Packet> c = p->Copy();
        PppHeader ppp;
        c->RemoveHeader(ppp);
        Ipv4Header ip;
        c->RemoveHeader(ip);
        if (ip.GetProtocol() != 17 || ip.GetDestination() != m_dst)
        {
            return false;
        }
        UdpHeader udp;
        c->RemoveHeader(udp);
        QuicHeader quic;
        c->RemoveHeader(quic);
        const uint32_t payload = c->GetSize();
        if (!quic.IsShort() || payload < m_frames.size())
        {
            return false;
        }
        QuicSubheader first;
        c->RemoveHeader(first);
        if (!first.IsStream())
        {
            return false;
        }
        std::vector<uint8_t> bytes(payload, 0);
        std::copy(m_frames.begin(), m_frames.end(), bytes.begin());
        p->RemoveAtEnd(payload);
        p->AddAtEnd(Create<Packet>(bytes.data(), bytes.size()));
        m_injected = true;
        return false;
    }

    void DoReset(void) override
    {
    }

    Ipv4Address m_dst;
    std::vector<uint8_t> m_frames;
    bool m_armed{false};
    bool m_injected{false};
};

/**
 * Two nodes on a link. After the handshake the client writes ten bytes on stream 0 and the packet
 * that carries them is rewritten on its way to the server.
 */
class InjectionScenario
{
  public:
    explicit InjectionScenario(std::vector<uint8_t> frames, uint32_t dataSize = 10)
        : m_frames(std::move(frames)),
          m_dataSize(dataSize)
    {
    }

    void Run(void)
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        link.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer devices = link.Install(nodes);
        m_injector = CreateObject<PayloadInjector>();
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.9.7.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        m_injector->Configure(interfaces.GetAddress(0), m_frames);
        devices.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(m_injector));

        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&InjectionScenario::Accepted, this));
        Simulator::Schedule(Seconds(0.1), [&]() {
            m_client = Socket::CreateSocket(nodes.Get(1), factory);
            m_client->SetConnectCallback(MakeCallback(&InjectionScenario::Connected, this),
                                         MakeNullCallback<void, Ptr<Socket>>());
            m_client->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(10));
        Simulator::Run();
        m_clientState = DynamicCast<QuicSocketBase>(m_client)->GetSocketState();
        if (m_server)
        {
            m_serverState = DynamicCast<QuicSocketBase>(m_server)->GetSocketState();
        }
        Simulator::Destroy();
    }

    uint64_t ServerRx(void) const
    {
        return m_serverRx;
    }

    bool Injected(void) const
    {
        return m_injector->Injected();
    }

    QuicSocket::QuicStates_t ClientState(void) const
    {
        return m_clientState;
    }

    QuicSocket::QuicStates_t ServerState(void) const
    {
        return m_serverState;
    }

  private:
    void Accepted(Ptr<Socket> socket, const Address&)
    {
        m_server = socket;
        socket->SetRecvCallback(MakeCallback(&InjectionScenario::Drain, this));
    }

    void Drain(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            m_serverRx += packet->GetSize();
        }
    }

    void Connected(Ptr<Socket> socket)
    {
        Simulator::Schedule(Seconds(0.5), [this, socket]() {
            m_injector->Arm();
            socket->Send(Create<Packet>(m_dataSize), 0);
        });
    }

    std::vector<uint8_t> m_frames;
    uint32_t m_dataSize;
    Ptr<PayloadInjector> m_injector;
    Ptr<Socket> m_client;
    Ptr<Socket> m_server;
    uint64_t m_serverRx{0};
    QuicSocket::QuicStates_t m_clientState{QuicSocket::IDLE};
    QuicSocket::QuicStates_t m_serverState{QuicSocket::IDLE};
};

} // namespace quic_test

#endif /* QUIC_INJECTION_H */
