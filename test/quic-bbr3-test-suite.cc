/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - BBR version 3 suite ("quic-bbr3").
 *
 * The congestion controller of draft-ietf-ccwg-bbr-07 on links with and without a shallow buffer
 * and random loss, compared with CUBIC and with BBR version 1, and the states it visits.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-bbr-v3.h"
#include "../model/quic-bbr.h"
#include "../model/quic-cubic.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"
#include "ns3/traffic-control-module.h"

#include <set>
#include <vector>

using namespace ns3;

namespace
{

/**
 * A client that sends data to a server over a bottleneck link.
 */
class BbrRig
{
  public:
    std::string cc{"ns3::QuicBbrV3"}; //!< the controller of the sender
    std::string rate{"20Mbps"};       //!< rate of the bottleneck
    std::string delay{"10ms"};        //!< one way delay
    std::string queue{"1000p"};       //!< queue of the bottleneck, in packets
    double loss{0.0};                 //!< random loss rate of the data direction
    uint64_t bytes{6000000};          //!< bytes to send
    double seconds{60};               //!< time limit

    uint64_t received{0};             //!< bytes the server read
    Time done;                        //!< time of the last byte
    std::set<uint8_t> modes;          //!< states the controller visited
    uint64_t lost{0};                 //!< packets declared lost

    /** Run the scenario. */
    void Run()
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamData", UintegerValue(1 << 26));
        Config::SetDefault("ns3::QuicSocketBase::MaxData", UintegerValue(1 << 27));
        Config::SetDefault("ns3::QuicSocketBase::SocketSndBufSize", UintegerValue(1 << 26));
        Config::SetDefault("ns3::QuicStreamBase::StreamSndBufSize", UintegerValue(1 << 26));
        Config::SetDefault("ns3::QuicL4Protocol::SocketType",
                           TypeIdValue(TypeId::LookupByName(cc)));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue(rate));
        link.SetChannelAttribute("Delay", StringValue(delay));
        link.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue(queue));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        TrafficControlHelper tch;
        tch.SetRootQueueDisc("ns3::FifoQueueDisc", "MaxSize", StringValue(queue));
        tch.Install(devices.Get(1));
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.9.1.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        if (loss > 0)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
            em->SetRate(loss);
            em->AssignStreams(1200);
            devices.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        }
        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&BbrRig::Accepted, this));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        client = DynamicCast<QuicSocketBase>(socket);
        client->TraceConnectWithoutContext("PacketLost", MakeCallback(&BbrRig::OnLost, this));
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(0.5), [this]() {
            Ptr<QuicBbrV3> v3 = DynamicCast<QuicBbrV3>(client->GetCongestionControl());
            if (v3 != nullptr)
            {
                v3->TraceConnectWithoutContext("BbrState", MakeCallback(&BbrRig::OnMode, this));
                modes.insert(QuicBbrV3::STARTUP); // the state the machine starts in
            }
            client->Send(Create<Packet>(bytes), 0);
        });
        Simulator::Stop(Seconds(seconds));
        Simulator::Run();
        Simulator::Destroy();
    }

    /** @return the goodput in Mbps from the start of the transfer to its end. */
    double GoodputMbps() const
    {
        const double elapsed = done.GetSeconds() - 0.5;
        return elapsed > 0 ? received * 8.0 / elapsed / 1e6 : 0;
    }

    Ptr<QuicSocketBase> client; //!< the sender

  private:
    void Accepted(Ptr<Socket> socket, const Address&)
    {
        socket->SetRecvCallback(MakeCallback(&BbrRig::Read, this));
    }

    void Read(Ptr<Socket> socket)
    {
        Ptr<Packet> p;
        while ((p = socket->Recv()) && p->GetSize() > 0)
        {
            received += p->GetSize();
            done = Simulator::Now();
        }
    }

    void OnLost(uint64_t, uint32_t, std::string)
    {
        ++lost;
    }

    void OnMode(uint8_t, uint8_t now)
    {
        modes.insert(now);
    }
};

/**
 * On a clean link it fills the pipe, goes through Startup and Drain to ProbeBW, probes upward and
 * visits ProbeRTT after the minimum RTT is ten seconds old.
 */
class Bbr3StatesTest : public TestCase
{
  public:
    Bbr3StatesTest()
        : TestCase("states of BBR version 3 on a clean link")
    {
    }

  private:
    void DoRun() override
    {
        BbrRig rig;
        rig.bytes = 60000000; // enough to last more than 20 seconds at 20 Mbps
        rig.seconds = 50;
        rig.Run();
        NS_TEST_EXPECT_MSG_GT(rig.GoodputMbps(), 14.0, "it fills most of the link");
        for (auto mode : {QuicBbrV3::STARTUP,
                          QuicBbrV3::DRAIN,
                          QuicBbrV3::PROBE_BW_DOWN,
                          QuicBbrV3::PROBE_BW_CRUISE,
                          QuicBbrV3::PROBE_BW_REFILL,
                          QuicBbrV3::PROBE_BW_UP,
                          QuicBbrV3::PROBE_RTT})
        {
            NS_TEST_EXPECT_MSG_EQ(rig.modes.count(mode),
                                  1,
                                  "visited " << QuicBbrV3::ModeName(mode));
        }
    }
};

/**
 * With a shallow buffer and 1% random loss CUBIC collapses, and BBR version 3 keeps most of the
 * link: the loss rate is below the threshold that makes it lower its bounds.
 */
class Bbr3LossTest : public TestCase
{
  public:
    Bbr3LossTest()
        : TestCase("random loss and a shallow buffer")
    {
    }

  private:
    void DoRun() override
    {
        double goodput[3];
        const char* names[3] = {"ns3::QuicBbrV3", "ns3::QuicCubic", "ns3::QuicBbr"};
        for (int k = 0; k < 3; ++k)
        {
            BbrRig rig;
            rig.cc = names[k];
            rig.loss = 0.01;
            rig.queue = "30p";
            rig.Run();
            NS_TEST_ASSERT_MSG_EQ(rig.received, rig.bytes, names[k] << " delivers the data");
            goodput[k] = rig.GoodputMbps();
        }
        NS_TEST_EXPECT_MSG_GT(goodput[0], 8.0, "BBR version 3 keeps a good part of 20 Mbps");
        NS_TEST_EXPECT_MSG_GT(goodput[0], goodput[1] * 1.5, "much more than CUBIC");
    }
};

/**
 * A loss rate above the threshold makes it lower the bound on the data in flight, and it still
 * delivers everything.
 */
class Bbr3HighLossTest : public TestCase
{
  public:
    Bbr3HighLossTest()
        : TestCase("loss above the threshold")
    {
    }

  private:
    void DoRun() override
    {
        BbrRig rig;
        rig.loss = 0.08;
        rig.bytes = 3000000;
        rig.Run();
        NS_TEST_EXPECT_MSG_EQ(rig.received, rig.bytes, "the data arrives");
        NS_TEST_EXPECT_MSG_GT(rig.lost, 10, "with losses");
    }
};

class QuicBbr3TestSuite : public TestSuite
{
  public:
    QuicBbr3TestSuite()
        : TestSuite("quic-bbr3", Type::UNIT)
    {
        AddTestCase(new Bbr3StatesTest, TestCase::Duration::QUICK);
        AddTestCase(new Bbr3LossTest, TestCase::Duration::QUICK);
        AddTestCase(new Bbr3HighLossTest, TestCase::Duration::QUICK);
    }
};

QuicBbr3TestSuite g_quicBbr3TestSuite;

} // namespace
