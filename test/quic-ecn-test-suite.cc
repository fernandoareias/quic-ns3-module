/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - ECN suite ("quic-ecn").
 *
 * Explicit Congestion Notification (RFC 9000, Section 13.4 and RFC 9002, Section 7.1): packets
 * marked with ECT(0), the counts that ACK_ECN frames carry, the validation of the path and the
 * response of the sender to the Congestion Experienced codepoint, with a CoDel queue that marks
 * instead of dropping.
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
#include "ns3/ppp-header.h"
#include "ns3/test.h"
#include "ns3/traffic-control-module.h"

#include <vector>

using namespace ns3;

namespace
{

/**
 * Counts the ECN codepoints of the packets that arrive at a device, and can clear them, as a
 * middlebox that does not support ECN does.
 */
class EcnObserver : public ErrorModel
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("ns3::QuicEcnObserver").SetParent<ErrorModel>().AddConstructor<EcnObserver>();
        return tid;
    }

    bool bleach{false};   //!< clear the ECN bits
    uint32_t marked{0};   //!< packets that arrived with ECT(0), ECT(1) or CE
    uint32_t packets{0};  //!< UDP packets that arrived

  private:
    bool DoCorrupt(Ptr<Packet> p) override
    {
        PppHeader ppp;
        p->RemoveHeader(ppp);
        Ipv4Header ip;
        p->RemoveHeader(ip);
        if (ip.GetProtocol() == 17)
        {
            ++packets;
            if (ip.GetEcn() != Ipv4Header::ECN_NotECT)
            {
                ++marked;
                if (bleach)
                {
                    ip.SetEcn(Ipv4Header::ECN_NotECT);
                }
            }
        }
        p->AddHeader(ip);
        p->AddHeader(ppp);
        return false;
    }

    void DoReset() override
    {
    }
};

/**
 * The client writes data to the server over a slow link, whose queue marks packets.
 */
class EcnRig
{
  public:
    bool clientEcn{false};      //!< EnableEcn on the client
    bool serverEcn{false};      //!< EnableEcn on the server
    bool bleach{false};         //!< the path clears the ECN bits
    bool codel{true};           //!< the client's queue is a CoDel queue that marks
    uint64_t bytes{600000};     //!< bytes the client writes

    uint64_t serverRx{0};       //!< bytes the server read
    uint64_t lost{0};           //!< packets the client declared lost
    uint64_t ackEcn{0};         //!< ACK_ECN frames the client received
    uint64_t maxCe{0};          //!< the largest CE count the client saw
    uint64_t countEvents{0};    //!< calls of the EcnCounts trace of the client
    uint32_t serverMarked{0};   //!< packets with ECN bits that reached the server device
    Time done;                  //!< when the last byte arrived
    uint32_t decreases{0};      //!< times the congestion window of the client went down

    /** Run the scenario. */
    void Run()
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue("4Mbps"));
        link.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        if (codel)
        {
            TrafficControlHelper tch;
            tch.SetRootQueueDisc("ns3::CoDelQueueDisc", "UseEcn", BooleanValue(true));
            tch.Install(devices.Get(1));
        }
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.3.2.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        Ptr<EcnObserver> observer = CreateObject<EcnObserver>();
        observer->bleach = bleach;
        devices.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(observer));

        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->SetAttribute("EnableEcn", BooleanValue(serverEcn));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&EcnRig::Accepted, this));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("EnableEcn", BooleanValue(clientEcn));
        client = DynamicCast<QuicSocketBase>(socket);
        client->TraceConnectWithoutContext("PacketLost", MakeCallback(&EcnRig::OnLost, this));
        client->TraceConnectWithoutContext("Rx", MakeCallback(&EcnRig::OnRx, this));
        client->TraceConnectWithoutContext("EcnCounts", MakeCallback(&EcnRig::OnCounts, this));
        client->TraceConnectWithoutContext("CongestionWindow", MakeCallback(&EcnRig::OnCwnd, this));
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(0.5), [this]() { client->Send(Create<Packet>(bytes)); });
        Simulator::Stop(Seconds(30));
        Simulator::Run();
        serverMarked = observer->marked;
        packetsToServer = observer->packets;
        Simulator::Destroy();
    }

    uint32_t packetsToServer{0}; //!< UDP packets that reached the server device
    Ptr<QuicSocketBase> client;  //!< the client socket

  private:
    void Accepted(Ptr<Socket> socket, const Address&)
    {
        socket->SetRecvCallback(MakeCallback(&EcnRig::ServerRead, this));
    }

    void ServerRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            serverRx += packet->GetSize();
            done = Simulator::Now();
        }
    }

    void OnLost(uint64_t, uint32_t, std::string)
    {
        ++lost;
    }

    void OnRx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (!h.IsShort())
        {
            return;
        }
        Ptr<Packet> rest = p->Copy();
        while (rest->GetSize() > 0)
        {
            QuicSubheader sub;
            rest->RemoveHeader(sub);
            if (!sub.IsValid())
            {
                return;
            }
            rest->RemoveAtStart(std::min<uint64_t>(sub.GetPayloadLength(rest->GetSize()),
                                                   rest->GetSize()));
            if (sub.GetFrameType() == QuicSubheader::ACK_ECN)
            {
                ++ackEcn;
                maxCe = std::max<uint64_t>(maxCe, sub.GetEcnCeCount());
            }
        }
    }

    void OnCounts(uint64_t, uint64_t)
    {
        ++countEvents;
    }

    void OnCwnd(uint32_t before, uint32_t now)
    {
        decreases += now < before ? 1 : 0;
    }
};

/**
 * Without ECN nothing is marked and nothing is counted; with it the packets are marked, the
 * server counts them and a queue that marks instead of dropping does not cost packets.
 */
class EcnMarkingTest : public TestCase
{
  public:
    EcnMarkingTest()
        : TestCase("marks, counts and the response to CE")
    {
    }

  private:
    void DoRun() override
    {
        EcnRig off;
        off.Run();
        NS_TEST_ASSERT_MSG_EQ(off.serverRx, off.bytes, "the data arrives without ECN");
        NS_TEST_EXPECT_MSG_EQ(off.serverMarked, 0, "no packet is marked");
        NS_TEST_EXPECT_MSG_EQ(off.ackEcn, 0, "no ACK_ECN frame");
        NS_TEST_EXPECT_MSG_GT(off.lost, 0, "the queue drops packets of an endpoint without ECN");

        EcnRig on;
        on.clientEcn = true;
        on.Run();
        NS_TEST_ASSERT_MSG_EQ(on.serverRx, on.bytes, "the data arrives with ECN");
        NS_TEST_EXPECT_MSG_GT(on.serverMarked, 10, "packets arrive marked");
        NS_TEST_EXPECT_MSG_GT(on.ackEcn, 0, "the server answers with ACK_ECN frames");
        NS_TEST_EXPECT_MSG_GT(on.countEvents, 0, "the counts are validated");
        NS_TEST_EXPECT_MSG_GT(on.maxCe, 0, "the queue marked packets with CE");
        NS_TEST_EXPECT_MSG_LT(on.lost, off.lost, "marking replaces dropping");
        NS_TEST_EXPECT_MSG_GT(on.decreases, 0, "CE makes the window shrink");
        NS_TEST_EXPECT_MSG_LT(on.lost, 5, "with almost no loss");

        // the server marks its packets too when it is asked to, and counts the client's
        EcnRig both;
        both.clientEcn = true;
        both.serverEcn = true;
        both.Run();
        NS_TEST_EXPECT_MSG_EQ(both.serverRx, both.bytes, "both ends with ECN");
    }
};

/**
 * A path that clears the ECN bits fails the validation: the sender stops marking after the first
 * packets, and the data arrives all the same (RFC 9000, Section 13.4.2).
 */
class EcnValidationTest : public TestCase
{
  public:
    EcnValidationTest()
        : TestCase("a path that clears the marks fails the validation")
    {
    }

  private:
    void DoRun() override
    {
        EcnRig rig;
        rig.clientEcn = true;
        rig.bleach = true;
        rig.codel = false;
        rig.Run();
        NS_TEST_ASSERT_MSG_EQ(rig.serverRx, rig.bytes, "the data arrives");
        NS_TEST_EXPECT_MSG_GT(rig.serverMarked, 0, "the first packets were marked");
        NS_TEST_EXPECT_MSG_LT(rig.serverMarked, 40, "and the marking stopped after the verdict");
        NS_TEST_EXPECT_MSG_GT(rig.packetsToServer, 200, "though there were many more packets");
        NS_TEST_EXPECT_MSG_EQ(rig.ackEcn, 0, "the server counted nothing");
    }
};

class QuicEcnTestSuite : public TestSuite
{
  public:
    QuicEcnTestSuite()
        : TestSuite("quic-ecn", Type::UNIT)
    {
        AddTestCase(new EcnMarkingTest, TestCase::Duration::QUICK);
        AddTestCase(new EcnValidationTest, TestCase::Duration::QUICK);
    }
};

QuicEcnTestSuite g_quicEcnTestSuite;

} // namespace
