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
#include "../model/quic-l5-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-stream-base.h"
#include "../model/quic-stream-id-tag.h"
#include "../model/quic-subheader.h"
#include "../model/quic-transport-parameters.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <map>
#include <memory>
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

/**
 * RFC 9287: an endpoint that announced grease_quic_bit accepts packets with a Fixed Bit of 0, and,
 * when the peer announced it too, sends some. A connection where one end did not announce it
 * never carries one.
 */
class GreaseTest : public TestCase
{
  public:
    GreaseTest()
        : TestCase("grease_quic_bit (RFC 9287)")
    {
    }

  private:
    /**
     * @param client GreaseQuicBit of the client.
     * @param server GreaseQuicBit of the server.
     * @param clientCleared set to the packets the client sent with a Fixed Bit of 0.
     * @param serverCleared set to the packets the server sent with a Fixed Bit of 0.
     * @param bytes set to the bytes the server read.
     */
    void Run(bool client,
             bool server,
             uint32_t& clientCleared,
             uint32_t& serverCleared,
             uint64_t& bytes)
    {
        struct State
        {
            uint32_t* cleared;
        };

        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        link.SetChannelAttribute("Delay", StringValue("5ms"));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.4.3.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        clientCleared = 0;
        serverCleared = 0;
        bytes = 0;
        auto count = [](uint32_t* counter) {
            return [counter](Ptr<const Packet> p) {
                std::vector<uint8_t> raw(p->GetSize());
                p->CopyData(raw.data(), raw.size());
                // PPP 2, IPv4 20 and UDP 8 bytes, then the first byte of the QUIC packet; a
                // long header packet keeps its form bit
                if (raw.size() > 30 && (raw[30] & 0x40) == 0)
                {
                    ++*counter;
                }
            };
        };
        devices.Get(1)->TraceConnectWithoutContext(
            "PhyTxEnd",
            Callback<void, Ptr<const Packet>>(count(&clientCleared)));
        devices.Get(0)->TraceConnectWithoutContext(
            "PhyTxEnd",
            Callback<void, Ptr<const Packet>>(count(&serverCleared)));
        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->SetAttribute("GreaseQuicBit", BooleanValue(server));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        uint64_t* total = &bytes;
        listener->SetAcceptCallback(
            MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
            Callback<void, Ptr<Socket>, const Address&>([total](Ptr<Socket> s, const Address&) {
                s->SetRecvCallback(Callback<void, Ptr<Socket>>([total](Ptr<Socket> r) {
                    Ptr<Packet> p;
                    while ((p = r->Recv()) && p->GetSize() > 0)
                    {
                        *total += p->GetSize();
                    }
                }));
                Simulator::Schedule(Seconds(0.3), [s]() { s->Send(Create<Packet>(100000)); });
            }));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("GreaseQuicBit", BooleanValue(client));
        socket->SetRecvCallback(Callback<void, Ptr<Socket>>([](Ptr<Socket> r) {
            Ptr<Packet> p;
            while ((p = r->Recv()) && p->GetSize() > 0)
            {
            }
        }));
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(0.3), [socket]() { socket->Send(Create<Packet>(100000)); });
        Simulator::Stop(Seconds(5));
        Simulator::Run();
        Simulator::Destroy();
    }

    void DoRun() override
    {
        uint32_t c;
        uint32_t s;
        uint64_t bytes;
        Run(false, false, c, s, bytes);
        NS_TEST_EXPECT_MSG_EQ(bytes, 100000, "without it the data arrives");
        NS_TEST_EXPECT_MSG_EQ(c + s, 0, "and the Fixed Bit is always 1");

        Run(true, false, c, s, bytes);
        NS_TEST_EXPECT_MSG_EQ(bytes, 100000, "one end only: the data arrives");
        NS_TEST_EXPECT_MSG_EQ(c + s, 0, "and nothing is greased");

        Run(true, true, c, s, bytes);
        NS_TEST_EXPECT_MSG_EQ(bytes, 100000, "both ends: the data arrives");
        NS_TEST_EXPECT_MSG_GT(c, 20, "the client clears the bit in some packets");
        NS_TEST_EXPECT_MSG_GT(s, 20, "so does the server");
    }
};

/**
 * The RESET_STREAM_AT frame: its bytes, and a stream that is reset after its first bytes were
 * delivered, even when packets are lost.
 */
class ResetStreamAtTest : public TestCase
{
  public:
    ResetStreamAtTest()
        : TestCase("RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset)")
    {
    }

  private:
    void OnReset(uint64_t id, uint64_t error, bool byPeer)
    {
        if (byPeer)
        {
            ++m_resets;
            m_resetError = error;
            m_bytesAtReset = m_bytes;
        }
    }

    void Accepted(Ptr<Socket> socket, const Address&)
    {
        m_server = DynamicCast<QuicSocketBase>(socket);
        socket->SetRecvCallback(MakeCallback(&ResetStreamAtTest::Read, this));
    }

    void Read(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            m_bytes += packet->GetSize();
        }
        if (!m_hooked && m_server->GetQuicL5()->SearchStream(0) != nullptr)
        {
            m_hooked = true;
            m_server->GetQuicL5()->SearchStream(0)->TraceConnectWithoutContext(
                "StreamReset",
                MakeCallback(&ResetStreamAtTest::OnReset, this));
        }
    }

    void DoRun() override
    {
        // the bytes of the frame: type 0x24, stream, error, final size, reliable size
        QuicSubheader frame = QuicSubheader::CreateResetStreamAt(4, 7, 1000, 600);
        Ptr<Packet> p = Create<Packet>();
        p->AddHeader(frame);
        std::vector<uint8_t> bytes(p->GetSize());
        p->CopyData(bytes.data(), bytes.size());
        const std::vector<uint8_t> expected{0x24, 0x04, 0x07, 0x43, 0xe8, 0x42, 0x58};
        NS_TEST_EXPECT_MSG_EQ((bytes == expected), true, "the bytes of the frame");
        QuicSubheader back;
        p->RemoveHeader(back);
        NS_TEST_EXPECT_MSG_EQ(back.IsResetStreamAt(), true, "read back");
        NS_TEST_EXPECT_MSG_EQ(back.GetReliableSize(), 600, "reliable size");
        // a Reliable Size larger than the Final Size is a FRAME_ENCODING_ERROR
        const uint8_t wrong[] = {0x24, 0x04, 0x07, 0x42, 0x58, 0x43, 0xe8};
        Ptr<Packet> bad = Create<Packet>(wrong, sizeof(wrong));
        QuicSubheader invalid;
        bad->RemoveHeader(invalid);
        NS_TEST_EXPECT_MSG_EQ(invalid.IsValid(), false, "reliable size above the final size");

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
        address.SetBase("10.6.5.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
        em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
        em->SetRate(0.2);
        em->AssignStreams(900);
        em->Disable();
        devices.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->SetAttribute("ResetStreamAt", BooleanValue(true));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&ResetStreamAtTest::Accepted, this));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("ResetStreamAt", BooleanValue(true));
        Ptr<QuicSocketBase> client = DynamicCast<QuicSocketBase>(socket);
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1), [client, em]() {
            em->Enable(); // the packets of the client now get lost
            client->Send(Create<Packet>(10000), 0);
        });
        Simulator::Schedule(Seconds(1) + MicroSeconds(100),
                            [client]() { client->Send(Create<Packet>(10000), 0); });
        Simulator::Schedule(Seconds(1) + MicroSeconds(200),
                            [client, this]() { m_accepted = client->ResetStreamAt(0, 77, 10000); });
        Simulator::Stop(Seconds(10));
        Simulator::Run();
        Simulator::Destroy();
        NS_TEST_ASSERT_MSG_EQ(m_accepted, true, "the frame was sent");
        NS_TEST_EXPECT_MSG_EQ(m_resets, 1, "the stream was reset once");
        NS_TEST_EXPECT_MSG_EQ(m_resetError, 77, "with the error code");
        NS_TEST_EXPECT_MSG_GT(m_bytesAtReset, 9999, "after the reliable bytes were delivered");
        NS_TEST_EXPECT_MSG_LT(m_bytes, 20001, "and not more than were written");
    }

    Ptr<QuicSocketBase> m_server; //!< the accepted connection
    bool m_hooked{false};         //!< the reset trace was connected
    bool m_accepted{false};       //!< ResetStreamAt () said yes
    uint32_t m_resets{0};         //!< resets seen by the server
    uint64_t m_resetError{0};     //!< their error code
    uint64_t m_bytes{0};          //!< bytes the server application read
    uint64_t m_bytesAtReset{0};   //!< bytes read when the reset came
};

/**
 * QUIC version 2 (RFC 9369) and the compatible version negotiation of RFC 9368.
 */
class VersionTest : public TestCase
{
  public:
    VersionTest()
        : TestCase("QUIC version 2 and compatible version negotiation")
    {
    }

  private:
    /** What a run of the scenario shows. */
    struct Result
    {
        bool connected{false};                //!< the client connected
        std::vector<uint32_t> clientVersions; //!< versions of the long header packets of the client
        std::vector<uint32_t> serverVersions; //!< ... and of the server
        uint8_t firstByte{0};                 //!< first byte of the first datagram of the client
    };

    /**
     * @param initial InitialVersion of the client.
     * @param clientVersions AvailableVersions of the client.
     * @param serverVersions AvailableVersions of the server.
     * @return what happened.
     */
    Result Run(uint32_t initial,
               const std::string& clientVersions,
               const std::string& serverVersions)
    {
        auto result = std::make_shared<Result>();
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        link.SetChannelAttribute("Delay", StringValue("5ms"));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.8.7.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        devices.Get(1)->TraceConnectWithoutContext(
            "PhyTxEnd",
            Callback<void, Ptr<const Packet>>([result](Ptr<const Packet> p) {
                if (result->firstByte == 0 && p->GetSize() > 30)
                {
                    uint8_t byte;
                    p->CopyData(&byte, 1); // placeholder, replaced below
                    std::vector<uint8_t> raw(31);
                    p->CopyData(raw.data(), 31);
                    result->firstByte = raw[30];
                }
            }));
        auto record = [](std::vector<uint32_t>* out) {
            return Callback<void, Ptr<const Packet>, const QuicHeader&, Ptr<const QuicSocketBase>>(
                [out](Ptr<const Packet>, const QuicHeader& h, Ptr<const QuicSocketBase>) {
                    if (h.IsLong() && !h.IsVersionNegotiation() && !h.IsRetry())
                    {
                        out->push_back(h.GetVersion());
                    }
                });
        };
        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->SetAttribute("AvailableVersions", StringValue(serverVersions));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        Ptr<QuicSocketBase> lq = DynamicCast<QuicSocketBase>(listener);
        lq->TraceConnectWithoutContext("Tx", record(&result->serverVersions));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("InitialVersion", UintegerValue(initial));
        socket->SetAttribute("AvailableVersions", StringValue(clientVersions));
        DynamicCast<QuicSocketBase>(socket)->TraceConnectWithoutContext(
            "Tx",
            record(&result->clientVersions));
        socket->SetConnectCallback(
            Callback<void, Ptr<Socket>>([result](Ptr<Socket>) { result->connected = true; }),
            MakeNullCallback<void, Ptr<Socket>>());
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(5));
        Simulator::Run();
        Simulator::Destroy();
        return *result;
    }

    void DoRun() override
    {
        const uint32_t v1 = 1;
        const uint32_t v2 = 0x6b3343cf;

        Result plain = Run(v1, "00000001", "00000001");
        NS_TEST_ASSERT_MSG_EQ(plain.connected, true, "version 1");
        for (uint32_t v : plain.clientVersions)
        {
            NS_TEST_EXPECT_MSG_EQ(v, v1, "version 1 on the wire");
        }
        NS_TEST_EXPECT_MSG_EQ(int(plain.firstByte & 0x30),
                              0x00,
                              "an Initial of version 1 has type 0");

        // the client starts in version 2
        Result full = Run(v2, "6b3343cf", "6b3343cf,00000001");
        NS_TEST_ASSERT_MSG_EQ(full.connected, true, "version 2");
        NS_TEST_ASSERT_MSG_GT(full.clientVersions.size(), 0, "packets");
        for (uint32_t v : full.clientVersions)
        {
            NS_TEST_EXPECT_MSG_EQ(v, v2, "client in version 2");
        }
        for (uint32_t v : full.serverVersions)
        {
            NS_TEST_EXPECT_MSG_EQ(v, v2, "server in version 2");
        }
        NS_TEST_EXPECT_MSG_EQ(int(full.firstByte & 0x30),
                              0x10,
                              "an Initial of version 2 has type 1");

        // the client starts in version 1 and offers version 2, which the server prefers
        Result upgrade = Run(v1, "6b3343cf,00000001", "6b3343cf,00000001");
        NS_TEST_ASSERT_MSG_EQ(upgrade.connected, true, "compatible negotiation");
        NS_TEST_ASSERT_MSG_GT(upgrade.clientVersions.size(), 1, "packets");
        NS_TEST_EXPECT_MSG_EQ(upgrade.clientVersions.front(), v1, "the first Initial is version 1");
        NS_TEST_EXPECT_MSG_EQ(upgrade.clientVersions.back(), v2, "the Handshake packets version 2");
        NS_TEST_ASSERT_MSG_GT(upgrade.serverVersions.size(), 0, "answers");
        for (uint32_t v : upgrade.serverVersions)
        {
            NS_TEST_EXPECT_MSG_EQ(v, v2, "the server answers in version 2");
        }

        // a server that does not have version 2 stays in version 1
        Result stay = Run(v1, "6b3343cf,00000001", "00000001");
        NS_TEST_ASSERT_MSG_EQ(stay.connected, true, "no common better version");
        for (uint32_t v : stay.serverVersions)
        {
            NS_TEST_EXPECT_MSG_EQ(v, v1, "the server stays in version 1");
        }

        // a version that the server does not know: Version Negotiation, then version 1
        Result negotiated = Run(0x2a3a4a5a, "00000001", "6b3343cf,00000001");
        NS_TEST_EXPECT_MSG_EQ(negotiated.connected, true, "Version Negotiation");
    }
};

/**
 * Receive timestamps (draft-ietf-quic-receive-ts): the frame on the wire, and a connection in
 * which the receiver of the data tells the sender when each packet arrived.
 */
class ReceiveTimestampTest : public TestCase
{
  public:
    ReceiveTimestampTest()
        : TestCase("receive timestamps in ACK frames")
    {
    }

  private:
    void OnTimestamp(uint64_t packet, uint64_t micro)
    {
        m_stamps[packet] = micro;
    }

    /** Run a transfer and collect the timestamps the sender is given. */
    void Transfer(uint32_t perAck, uint32_t exponent, std::map<uint64_t, uint64_t>& out)
    {
        m_stamps.clear();
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
        address.SetBase("10.1.9.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        // both ends announce the parameters: the exponent is that of the end that sends the frame
        listener->SetAttribute("MaxReceiveTimestampsPerAck", UintegerValue(perAck));
        listener->SetAttribute("ReceiveTimestampsExponent", UintegerValue(exponent));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(
            MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
            Callback<void, Ptr<Socket>, const Address&>([](Ptr<Socket> sock, const Address&) {
                sock->SetRecvCallback(Callback<void, Ptr<Socket>>([](Ptr<Socket> r) {
                    Ptr<Packet> p;
                    while ((p = r->Recv()) && p->GetSize() > 0)
                    {
                    }
                }));
            }));
        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("MaxReceiveTimestampsPerAck", UintegerValue(perAck));
        Ptr<QuicSocketBase> client = DynamicCast<QuicSocketBase>(socket);
        client->TraceConnectWithoutContext("ReceiveTimestamp",
                                           MakeCallback(&ReceiveTimestampTest::OnTimestamp, this));
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(0.5), [client]() { client->Send(Create<Packet>(200000), 0); });
        Simulator::Stop(Seconds(5));
        Simulator::Run();
        Simulator::Destroy();
        out = m_stamps;
    }

    void DoRun() override
    {
        // the frame: type 0x03178307 as a varint of four bytes, then the ACK fields and the
        // ranges of timestamps
        std::vector<uint64_t> gaps;
        std::vector<uint64_t> blocks;
        QuicSubheader ack = QuicSubheader::CreateAck(20, 0, 15, gaps, blocks);
        QuicSubheader::TimestampRange first;
        first.deltaLargest = 0;
        first.deltas = {5000, 120, 90};
        QuicSubheader::TimestampRange second;
        second.deltaLargest = 6;
        second.deltas = {300};
        ack.SetTimestampRanges({first, second});
        Ptr<Packet> p = Create<Packet>();
        p->AddHeader(ack);
        std::vector<uint8_t> bytes(p->GetSize());
        p->CopyData(bytes.data(), bytes.size());
        NS_TEST_EXPECT_MSG_EQ(int(bytes[0]), 0x83, "the type is a varint of four bytes");
        NS_TEST_EXPECT_MSG_EQ(int(bytes[1]), 0x17, "0x03178307");
        NS_TEST_EXPECT_MSG_EQ(int(bytes[3]), 0x07, "without ECN counts");
        QuicSubheader back;
        p->RemoveHeader(back);
        NS_TEST_ASSERT_MSG_EQ(back.IsValid(), true, "valid");
        NS_TEST_EXPECT_MSG_EQ(back.HasReceiveTimestamps(), true, "with timestamps");
        NS_TEST_EXPECT_MSG_EQ(back.GetTimestampRanges().size(), 2, "two ranges");
        NS_TEST_EXPECT_MSG_EQ(back.GetTimestampRanges()[0].deltas.size(), 3, "three deltas");
        NS_TEST_EXPECT_MSG_EQ(back.GetTimestampRanges()[1].deltaLargest, 6, "the second range");
        NS_TEST_EXPECT_MSG_EQ(back.IsAllowedIn(QuicPacketType::ONE_RTT), true, "1-RTT");
        NS_TEST_EXPECT_MSG_EQ(back.IsAllowedIn(QuicPacketType::HANDSHAKE), false, "only 1-RTT");
        ack.SetEcnCounts(4, 0, 1);
        NS_TEST_EXPECT_MSG_EQ(ack.GetFrameType(), QuicSubheader::ACK_RECEIVE_TIMESTAMPS_ECN, "ECN");

        // a range that reaches below packet number 0 is a FRAME_ENCODING_ERROR
        QuicSubheader::TimestampRange wrong;
        wrong.deltaLargest = 19;
        wrong.deltas = {1, 1, 1};
        QuicSubheader bad = QuicSubheader::CreateAck(20, 0, 15, gaps, blocks);
        bad.SetTimestampRanges({wrong});
        Ptr<Packet> q = Create<Packet>();
        q->AddHeader(bad);
        QuicSubheader invalid;
        q->RemoveHeader(invalid);
        NS_TEST_EXPECT_MSG_EQ(invalid.IsValid(), false, "below packet number 0");

        // the exponent is at most 20
        QuicTransportParameters tp =
            QuicTransportParameters::CreateTransportParameters(1, 1, 1, 1, 1472, 3, 1);
        tp.SetMaxReceiveTimestampsPerAck(10);
        tp.SetReceiveTimestampsExponent(21);
        Buffer buffer;
        buffer.AddAtStart(tp.GetSerializedSize());
        tp.Serialize(buffer.Begin());
        QuicTransportParameters read;
        read.Deserialize(buffer.Begin());
        NS_TEST_EXPECT_MSG_EQ(read.IsValid(), false, "an exponent above 20");

        std::map<uint64_t, uint64_t> none;
        Transfer(0, 0, none);
        NS_TEST_EXPECT_MSG_EQ(none.size(), 0, "nothing is reported when the sender takes none");

        std::map<uint64_t, uint64_t> stamps;
        Transfer(20, 0, stamps);
        NS_TEST_ASSERT_MSG_GT(stamps.size(), 50, "the receiver reports many arrivals");
        // the data packets arrive one after the other on a link of 10 Mbps: about 1.2 ms apart
        uint64_t previousPacket = 0;
        uint64_t previousTime = 0;
        size_t spaced = 0;
        size_t pairs = 0;
        for (const auto& entry : stamps)
        {
            if (previousPacket != 0 && entry.first == previousPacket + 1)
            {
                NS_TEST_EXPECT_MSG_GT(entry.second, previousTime, "later packets arrive later");
                const uint64_t gap = entry.second - previousTime;
                ++pairs;
                spaced += (gap > 800 && gap < 1700) ? 1 : 0;
            }
            previousPacket = entry.first;
            previousTime = entry.second;
        }
        NS_TEST_EXPECT_MSG_GT(pairs, 30, "consecutive packets");
        NS_TEST_EXPECT_MSG_GT(spaced * 10, pairs * 7, "spaced by the serialization time");

        // with an exponent of 3 the times are rounded to eight microseconds
        std::map<uint64_t, uint64_t> coarse;
        Transfer(20, 3, coarse);
        NS_TEST_ASSERT_MSG_GT(coarse.size(), 50, "reported");
        size_t multiples = 0;
        for (const auto& entry : coarse)
        {
            multiples += (entry.second % 8 == 0) ? 1 : 0;
        }
        NS_TEST_EXPECT_MSG_EQ(multiples, coarse.size(), "multiples of 2^3 microseconds");
    }

    std::map<uint64_t, uint64_t> m_stamps; //!< timestamps of the run
};

class QuicExtensionsTestSuite : public TestSuite
{
  public:
    QuicExtensionsTestSuite()
        : TestSuite("quic-extensions", Type::UNIT)
    {
        AddTestCase(new ExtensionWireTest, TestCase::Duration::QUICK);
        AddTestCase(new DatagramTest, TestCase::Duration::QUICK);
        AddTestCase(new GreaseTest, TestCase::Duration::QUICK);
        AddTestCase(new ResetStreamAtTest, TestCase::Duration::QUICK);
        AddTestCase(new VersionTest, TestCase::Duration::QUICK);
        AddTestCase(new ReceiveTimestampTest, TestCase::Duration::QUICK);
    }
};

QuicExtensionsTestSuite g_quicExtensionsTestSuite;

} // namespace
