/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - datagram suite ("quic-datagrams").
 *
 * The UDP datagrams that carry QUIC packets (RFC 9000, Section 12.2 and 14): several packets in
 * one datagram, each long header packet with its own Length and a short header packet last, and
 * datagrams that are expanded to a minimum size with PADDING frames.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-header.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-subheader.h"

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <functional>
#include <vector>

using namespace ns3;

namespace
{

/**
 * Two nodes with an open connection, in which the test sends datagrams that it builds.
 */
class DatagramRig
{
  public:
    Ptr<QuicSocketBase> client;       //!< the client socket
    Ptr<QuicSocketBase> server;       //!< the server socket of the connection
    uint64_t serverRx{0};             //!< bytes the server application read
    std::vector<uint32_t> clientWire; //!< UDP payload of every datagram the client sent

    /**
     * Connect, wait for the connection to open and run the action.
     *
     * @param action what the test does with the open connection.
     */
    void Run(std::function<void(DatagramRig&)> action)
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        link.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.9.8.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        devices.Get(1)->TraceConnectWithoutContext("PhyTxEnd",
                                                   MakeCallback(&DatagramRig::OnClientPhyTx, this));

        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&DatagramRig::Accepted, this));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        client = DynamicCast<QuicSocketBase>(socket);
        Simulator::Schedule(Seconds(0.1), [this, socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        l4 = nodes.Get(1)->GetObject<QuicL4Protocol>();
        Simulator::Schedule(Seconds(1.0), [this, action]() { action(*this); });
        Simulator::Stop(Seconds(5));
        Simulator::Run();
        state = server ? server->GetSocketState() : QuicSocket::IDLE;
        clientState = client->GetSocketState();
        Simulator::Destroy();
    }

    Ptr<QuicL4Protocol> l4;                                 //!< the client's QUIC protocol
    QuicSocket::QuicStates_t state{QuicSocket::IDLE};       //!< server state at the end
    QuicSocket::QuicStates_t clientState{QuicSocket::IDLE}; //!< client state at the end

  private:
    void Accepted(Ptr<Socket> socket, const Address&)
    {
        server = DynamicCast<QuicSocketBase>(socket);
        socket->SetRecvCallback(MakeCallback(&DatagramRig::Read, this));
    }

    void Read(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            serverRx += packet->GetSize();
        }
    }

    void OnClientPhyTx(Ptr<const Packet> packet)
    {
        clientWire.push_back(packet->GetSize() - 2 - 20 - 8); // PPP, IPv4 and UDP headers
    }
};

/**
 * The frames of a packet.
 *
 * @param frames the frames, each with its data after it.
 * @return the packet.
 */
Ptr<Packet>
Frames(const std::vector<std::pair<QuicSubheader, uint32_t>>& frames)
{
    Ptr<Packet> packet = Create<Packet>();
    for (auto it = frames.rbegin(); it != frames.rend(); ++it)
    {
        Ptr<Packet> frame = Create<Packet>(it->second);
        frame->AddHeader(it->first);
        frame->AddAtEnd(packet);
        packet = frame;
    }
    return packet;
}

/**
 * A Handshake packet and a 1-RTT packet in one datagram: both are delivered.
 */
class DatagramCoalescedTest : public TestCase
{
  public:
    DatagramCoalescedTest()
        : TestCase("datagrams: a Handshake packet and a 1-RTT packet in one datagram are both read")
    {
    }

  private:
    void DoRun() override
    {
        DatagramRig rig;
        rig.Run([](DatagramRig& r) {
            const QuicConnectionId dcid = r.client->GetDestCid();
            const QuicConnectionId scid = r.client->GetConnectionId();
            // the packet numbers are far above the ones of the connection, so that no packet in
            // flight is mistaken for these
            std::vector<std::pair<QuicHeader, Ptr<Packet>>> packets;
            packets.emplace_back(
                QuicHeader::CreateHandshake(dcid, scid, QUIC_VERSION, QuicPacketNumber(1000)),
                Frames({{QuicSubheader::CreatePing(), 0}}));
            packets.emplace_back(
                QuicHeader::CreateShort(dcid, QuicPacketNumber(1001)),
                Frames({{QuicSubheader::CreateStreamSubHeader(0, 0, 5, false, true, true), 5}}));
            r.l4->SendDatagram(r.client, packets);
        });
        NS_TEST_ASSERT_MSG_EQ(rig.serverRx,
                              5u,
                              "the data of the 1-RTT packet that came behind the Handshake packet");
        NS_TEST_ASSERT_MSG_EQ(rig.state, QuicSocket::OPEN, "server state");
        NS_TEST_ASSERT_MSG_EQ(rig.clientState, QuicSocket::OPEN, "client state");
    }
};

/**
 * A datagram of several packets is expanded to the size asked for, in its last packet.
 */
class DatagramPaddingTest : public TestCase
{
  public:
    DatagramPaddingTest()
        : TestCase("datagrams: the minimum size of a datagram is reached with PADDING in its last "
                   "packet")
    {
    }

  private:
    void DoRun() override
    {
        DatagramRig rig;
        uint32_t before = 0;
        rig.Run([&before](DatagramRig& r) {
            before = r.clientWire.size();
            const QuicConnectionId dcid = r.client->GetDestCid();
            const QuicConnectionId scid = r.client->GetConnectionId();
            std::vector<std::pair<QuicHeader, Ptr<Packet>>> packets;
            packets.emplace_back(
                QuicHeader::CreateHandshake(dcid, scid, QUIC_VERSION, QuicPacketNumber(2000)),
                Frames({{QuicSubheader::CreatePing(), 0}}));
            packets.emplace_back(QuicHeader::CreateShort(dcid, QuicPacketNumber(2001)),
                                 Frames({{QuicSubheader::CreatePing(), 0}}));
            r.l4->SendDatagram(r.client, packets, 1200);
        });
        NS_TEST_ASSERT_MSG_GT(rig.clientWire.size(), before, "the datagram was sent");
        NS_TEST_ASSERT_MSG_EQ(rig.clientWire[before], 1200u, "bytes of the datagram");
        NS_TEST_ASSERT_MSG_EQ(rig.state, QuicSocket::OPEN, "server state");
    }
};

class QuicDatagramsTestSuite : public TestSuite
{
  public:
    QuicDatagramsTestSuite()
        : TestSuite("quic-datagrams", Type::UNIT)
    {
        AddTestCase(new DatagramCoalescedTest, TestCase::Duration::QUICK);
        AddTestCase(new DatagramPaddingTest, TestCase::Duration::QUICK);
    }
};

QuicDatagramsTestSuite g_quicDatagramsTestSuite;

} // namespace
