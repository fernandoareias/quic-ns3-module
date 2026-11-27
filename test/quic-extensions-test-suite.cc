/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - extensions suite ("quic-extensions").
 *
 * The extensions of the IETF QUIC working group that are not part of the core RFCs: unreliable
 * datagrams (RFC 9221), and the transport parameters that announce them.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-header.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-subheader.h"
#include "../model/quic-transport-parameters.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <set>
#include <vector>

using namespace ns3;

namespace
{

/**
 * The bytes of the DATAGRAM frames and of the parameters that announce the extensions.
 */
class ExtensionWireTest : public TestCase
{
  public:
    ExtensionWireTest()
        : TestCase("DATAGRAM frames and extension transport parameters on the wire")
    {
    }

  private:
    void DoRun() override
    {
        // DATAGRAM with a Length (0x31): the type, the length and the data (RFC 9221, Section 4)
        Ptr<Packet> p = Create<Packet>(5);
        p->AddHeader(QuicSubheader::CreateDatagram(5));
        std::vector<uint8_t> bytes(p->GetSize());
        p->CopyData(bytes.data(), bytes.size());
        NS_TEST_ASSERT_MSG_EQ(bytes.size(), 7, "type, length and five bytes");
        NS_TEST_EXPECT_MSG_EQ(int(bytes[0]), 0x31, "type");
        NS_TEST_EXPECT_MSG_EQ(int(bytes[1]), 5, "length");
        QuicSubheader back;
        p->RemoveHeader(back);
        NS_TEST_EXPECT_MSG_EQ(back.IsValid(), true, "valid");
        NS_TEST_EXPECT_MSG_EQ(back.IsDatagram(), true, "a DATAGRAM frame");
        NS_TEST_EXPECT_MSG_EQ(back.GetPayloadLength(100), 5, "five bytes of data");

        // DATAGRAM without a Length (0x30) runs to the end of the packet
        const uint8_t plain[] = {0x30, 1, 2, 3, 4};
        Ptr<Packet> q = Create<Packet>(plain, sizeof(plain));
        QuicSubheader open;
        q->RemoveHeader(open);
        NS_TEST_EXPECT_MSG_EQ(open.IsValid(), true, "valid");
        NS_TEST_EXPECT_MSG_EQ(open.GetPayloadLength(q->GetSize()), 4, "everything that is left");

        // only 0-RTT and 1-RTT packets may carry it
        NS_TEST_EXPECT_MSG_EQ(back.IsAllowedIn(QuicPacketType::ONE_RTT), true, "1-RTT");
        NS_TEST_EXPECT_MSG_EQ(back.IsAllowedIn(QuicPacketType::ZERO_RTT), true, "0-RTT");
        NS_TEST_EXPECT_MSG_EQ(back.IsAllowedIn(QuicPacketType::INITIAL), false, "Initial");
        NS_TEST_EXPECT_MSG_EQ(back.IsAllowedIn(QuicPacketType::HANDSHAKE), false, "Handshake");

        // the parameters: 0x20 with a value, 0x2ab2 and 0x1d empty
        QuicTransportParameters tp =
            QuicTransportParameters::CreateTransportParameters(1, 1, 1, 1, 1472, 3, 1);
        tp.SetMaxDatagramFrameSize(1200);
        tp.SetGreaseQuicBit(true);
        tp.SetResetStreamAt(true);
        Buffer buffer;
        buffer.AddAtStart(tp.GetSerializedSize());
        tp.Serialize(buffer.Begin());
        std::vector<uint8_t> raw(buffer.GetSize());
        buffer.CopyData(raw.data(), raw.size());
        auto has = [&raw](std::vector<uint8_t> pattern) {
            return std::search(raw.begin(), raw.end(), pattern.begin(), pattern.end()) != raw.end();
        };
        NS_TEST_EXPECT_MSG_EQ(has({0x20, 0x02, 0x44, 0xb0}), true, "max_datagram_frame_size 1200");
        NS_TEST_EXPECT_MSG_EQ(has({0x6a, 0xb2, 0x00}), true, "grease_quic_bit, empty");
        NS_TEST_EXPECT_MSG_EQ(has({0x1d, 0x00}), true, "reset_stream_at, empty");
        QuicTransportParameters read;
        read.Deserialize(buffer.Begin());
        NS_TEST_EXPECT_MSG_EQ(read.IsValid(), true, "valid");
        NS_TEST_EXPECT_MSG_EQ(read.GetMaxDatagramFrameSize(), 1200, "size");
        NS_TEST_EXPECT_MSG_EQ(read.GetGreaseQuicBit(), true, "grease");
        NS_TEST_EXPECT_MSG_EQ(read.GetResetStreamAt(), true, "reset at");
        NS_TEST_EXPECT_MSG_EQ((read == tp), true, "equal");

        // a value on a parameter that has none is an error (RFC 9287, Section 3)
        const uint8_t bad[] = {0x04, 0x6a, 0xb2, 0x01, 0x00};
        Buffer bb;
        bb.AddAtStart(sizeof(bad));
        Buffer::Iterator it = bb.Begin();
        for (uint8_t b : bad)
        {
            it.WriteU8(b);
        }
        QuicTransportParameters invalid;
        invalid.Deserialize(bb.Begin());
        NS_TEST_EXPECT_MSG_EQ(invalid.IsValid(), false, "grease_quic_bit with a value");
    }
};

/**
 * Two nodes that exchange datagrams.
 */
class DatagramRig
{
  public:
    uint32_t clientMax{1200};  //!< MaxDatagramFrameSize of the client
    uint32_t serverMax{1200};  //!< MaxDatagramFrameSize of the server
    double loss{0.0};          //!< loss rate of the link in each direction
    uint32_t count{0};         //!< datagrams the client writes
    uint32_t size{100};        //!< bytes of each

    std::vector<int> results;          //!< what SendDatagram returned
    std::vector<uint32_t> received;    //!< identities of the datagrams the server got
    uint64_t framesOnWire{0};          //!< DATAGRAM frames the client sent
    uint32_t maxSize{0};               //!< GetMaxDatagramSize () of the client once open
    uint64_t dropped{0};               //!< DatagramDropped trace calls of the client
    bool connected{false};             //!< the connection came up

    /** Run the scenario. */
    void Run()
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
        address.SetBase("10.2.1.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        if (loss > 0)
        {
            for (uint32_t k = 0; k < 2; ++k)
            {
                Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
                em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
                em->SetRate(loss);
                em->AssignStreams(800 + k);
                devices.Get(k)->SetAttribute("ReceiveErrorModel", PointerValue(em));
            }
        }
        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->SetAttribute("MaxDatagramFrameSize", UintegerValue(serverMax));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&DatagramRig::Accepted, this));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("MaxDatagramFrameSize", UintegerValue(clientMax));
        client = DynamicCast<QuicSocketBase>(socket);
        client->TraceConnectWithoutContext("Tx", MakeCallback(&DatagramRig::OnTx, this));
        client->TraceConnectWithoutContext("DatagramDropped",
                                           MakeCallback(&DatagramRig::OnDropped, this));
        socket->SetConnectCallback(MakeCallback(&DatagramRig::OnConnected, this),
                                   MakeNullCallback<void, Ptr<Socket>>());
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1), &DatagramRig::TrySend, this);
        Simulator::Stop(Seconds(10));
        Simulator::Run();
        Simulator::Destroy();
    }

    Ptr<QuicSocketBase> client; //!< the client socket
    Ptr<QuicSocketBase> server; //!< the socket of the accepted connection

  private:
    /** Write the datagrams once the connection is open. */
    void TrySend()
    {
        if (!connected || server == nullptr || server->GetSocketState() != QuicSocket::OPEN)
        {
            Simulator::Schedule(MilliSeconds(100), &DatagramRig::TrySend, this);
            return;
        }
        maxSize = client->GetMaxDatagramSize();
        for (uint32_t k = 0; k < count; ++k)
        {
            // the first four bytes tell which datagram it is
            std::vector<uint8_t> bytes(size, 0);
            for (int b = 0; b < 4; ++b)
            {
                bytes[b] = static_cast<uint8_t>(k >> (8 * b));
            }
            results.push_back(client->SendDatagram(Create<Packet>(bytes.data(), size)));
        }
    }

    void Accepted(Ptr<Socket> socket, const Address&)
    {
        server = DynamicCast<QuicSocketBase>(socket);
        server->SetDatagramCallback(MakeCallback(&DatagramRig::OnDatagram, this));
    }

    void OnDatagram(Ptr<QuicSocketBase>, Ptr<Packet> p)
    {
        uint8_t head[4];
        p->CopyData(head, 4);
        received.push_back(head[0] | (head[1] << 8) | (head[2] << 16) | (head[3] << 24));
    }

    void OnConnected(Ptr<Socket>)
    {
        connected = true;
    }

    void OnDropped(Ptr<const Packet>)
    {
        ++dropped;
    }

    void OnTx(Ptr<const Packet> p, const QuicHeader&, Ptr<const QuicSocketBase>)
    {
        Ptr<Packet> rest = p->Copy();
        while (rest->GetSize() > 0)
        {
            QuicSubheader sub;
            rest->RemoveHeader(sub);
            if (!sub.IsValid())
            {
                return;
            }
            framesOnWire += sub.IsDatagram() ? 1 : 0;
            rest->RemoveAtStart(std::min<uint64_t>(sub.GetPayloadLength(rest->GetSize()),
                                                   rest->GetSize()));
        }
    }
};

/**
 * Datagrams cross a clean link in order, are refused when the peer does not take them or they are
 * too large, and on a link that loses packets some of them are lost for good.
 */
class DatagramTest : public TestCase
{
  public:
    DatagramTest()
        : TestCase("DATAGRAM frames (RFC 9221)")
    {
    }

  private:
    void DoRun() override
    {
        DatagramRig clean;
        clean.count = 50;
        clean.Run();
        NS_TEST_ASSERT_MSG_EQ(clean.connected, true, "connected");
        NS_TEST_EXPECT_MSG_EQ(clean.received.size(), 50, "all arrive");
        for (size_t k = 0; k < clean.received.size(); ++k)
        {
            NS_TEST_EXPECT_MSG_EQ(clean.received[k], k, "in order");
        }
        for (int r : clean.results)
        {
            NS_TEST_EXPECT_MSG_EQ(r, 100, "accepted");
        }
        NS_TEST_EXPECT_MSG_GT(clean.maxSize, 1000, "a datagram of 1000 bytes fits");
        NS_TEST_EXPECT_MSG_LT(clean.maxSize, 1200, "less than the frame size of the peer");

        DatagramRig none;
        none.serverMax = 0;
        none.count = 3;
        none.Run();
        NS_TEST_EXPECT_MSG_EQ(none.maxSize, 0, "the peer takes none");
        for (int r : none.results)
        {
            NS_TEST_EXPECT_MSG_EQ(r, -1, "refused");
        }
        NS_TEST_EXPECT_MSG_EQ(none.received.size(), 0, "nothing arrives");
        NS_TEST_EXPECT_MSG_EQ(none.dropped, 3, "and the drops are traced");

        DatagramRig large;
        large.size = 1250; // more than the frame size that the peer announced
        large.count = 2;
        large.Run();
        NS_TEST_ASSERT_MSG_GT(large.results.size(), 0, "tried");
        NS_TEST_EXPECT_MSG_EQ(large.results[0], -1, "too large for the peer");

        DatagramRig lossy;
        lossy.loss = 0.2;
        lossy.count = 400;
        lossy.Run();
        NS_TEST_ASSERT_MSG_EQ(lossy.connected, true, "connected despite the loss");
        NS_TEST_EXPECT_MSG_GT(lossy.received.size(), 150, "most arrive");
        NS_TEST_EXPECT_MSG_LT(lossy.received.size(), 380, "and some are lost for good");
        std::set<uint32_t> unique(lossy.received.begin(), lossy.received.end());
        NS_TEST_EXPECT_MSG_EQ(unique.size(), lossy.received.size(), "none arrives twice");
        NS_TEST_EXPECT_MSG_EQ(lossy.framesOnWire, 400, "each one was sent once, never again");
    }
};

class QuicExtensionsTestSuite : public TestSuite
{
  public:
    QuicExtensionsTestSuite()
        : TestSuite("quic-extensions", Type::UNIT)
    {
        AddTestCase(new ExtensionWireTest, TestCase::Duration::QUICK);
        AddTestCase(new DatagramTest, TestCase::Duration::QUICK);
    }
};

QuicExtensionsTestSuite g_quicExtensionsTestSuite;

} // namespace
