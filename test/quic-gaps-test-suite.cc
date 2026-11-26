/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - reproductions of the conformance gaps ("quic-gaps").
 *
 * Reading the code against RFC 9000 and RFC 9002 found defects that do not depend on the wire
 * format. Each case here reproduces one of them and passes only once the defect is gone. The cases
 * do nothing unless QUIC_GAPS is set in the environment, so the suite is green until a phase of the
 * RFC alignment fixes a case; that phase then moves the case to a regular suite and removes it
 * from here.
 *
 *   QUIC_GAPS=1 build/utils/ns3-dev-test-runner-default --suite=quic-gaps --verbose
 *
 * A suite stops at its first failing case, so QUIC_GAPS can also name the cases to run, separated
 * by commas: ack-frequency-type, ack-ecn-is-ack, ack-ecn-connection, empty-stream-frame,
 * unknown-frame-type.
 *
 * Reproduced here:
 *   - ACK_FREQUENCY is written with a one byte frame type, where RFC 9000 s12.4 needs a varint
 *     (0x40 0xaf).
 *   - ACK_ECN (0x03) is not an ACK for IsAck(), and a peer that sends one closes the connection.
 *   - A frame of an undefined type closes the connection with FRAME_ENCODING_ERROR, but builds
 *     with assertions abort on it.
 *   - A STREAM frame with the LEN bit and a length of zero (the way a bare FIN is written) is read
 *     as "up to the end of the packet" and swallows the frames behind it.
 *
 * Found but not reproduced yet (the phase that fixes each one adds its test):
 *   - the final size of a stream is compared with the offset, not with offset plus length (F4);
 *   - a duplicate STREAM frame after DATA_READ, and a RESET_STREAM after all the data arrived,
 *     abort the connection (F4);
 *   - Version Negotiation does not echo the connection ids of the client (F2);
 *   - loss detection skips an ACK whose largest packet number is not in the sent list, as happens
 *     for packets that carry only an ACK (F8);
 *   - a packet held back by the anti-amplification limit stays in the sent list (F7);
 *   - the client confirms the handshake on the first Handshake packet and not on HANDSHAKE_DONE
 *     (F8);
 *   - the RTO trace never changes and the traces of an accepted socket are not connected (F1).
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
#include "ns3/test.h"

#include <cstdlib>
#include <string>
#include <vector>

using namespace ns3;

namespace
{

/**
 * @param key name of a case.
 * @return true when the case is enabled in the environment: QUIC_GAPS is 1 for every case, or a
 * list of case names.
 */
bool
GapsEnabled(const std::string& key)
{
    const char* value = std::getenv("QUIC_GAPS");
    if (value == nullptr)
    {
        return false;
    }
    const std::string list(value);
    return list == "1" || list.find(key) != std::string::npos;
}

/**
 * Serialize a header into bytes.
 *
 * @param header the header.
 * @return the bytes.
 */
std::vector<uint8_t>
GapBytes(const Header& header)
{
    Buffer buffer;
    buffer.AddAtStart(header.GetSerializedSize());
    header.Serialize(buffer.Begin());
    std::vector<uint8_t> bytes(buffer.GetSize());
    buffer.CopyData(bytes.data(), bytes.size());
    return bytes;
}

/**
 * Replaces the frames of the first QUIC short header packet that is sent to a node, once armed and
 * when that packet starts with a STREAM frame. The packet keeps its headers and its size: the
 * frames given are followed by zero bytes (PADDING).
 */
class PayloadInjector : public ErrorModel
{
  public:
    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::QuicGapPayloadInjector")
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
class GapScenario
{
  public:
    explicit GapScenario(std::vector<uint8_t> frames)
        : m_frames(std::move(frames))
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
                                    MakeCallback(&GapScenario::Accepted, this));
        Simulator::Schedule(Seconds(0.1), [&]() {
            m_client = Socket::CreateSocket(nodes.Get(1), factory);
            m_client->SetConnectCallback(MakeCallback(&GapScenario::Connected, this),
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
        socket->SetRecvCallback(MakeCallback(&GapScenario::Drain, this));
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
            socket->Send(Create<Packet>(10), 0);
        });
    }

    std::vector<uint8_t> m_frames;
    Ptr<PayloadInjector> m_injector;
    Ptr<Socket> m_client;
    Ptr<Socket> m_server;
    uint64_t m_serverRx{0};
    QuicSocket::QuicStates_t m_clientState{QuicSocket::IDLE};
    QuicSocket::QuicStates_t m_serverState{QuicSocket::IDLE};
};

/**
 * ACK_FREQUENCY carries the frame type 0xaf, which does not fit in the six bits of a one byte
 * variable-length integer: it is written 0x40 0xaf (RFC 9000 s12.4, s16).
 */
class GapAckFrequencyTypeTest : public TestCase
{
  public:
    GapAckFrequencyTypeTest()
        : TestCase("gap: the ACK_FREQUENCY frame type is a variable-length integer")
    {
    }

  private:
    void DoRun() override
    {
        if (!GapsEnabled("ack-frequency-type"))
        {
            return;
        }
        std::vector<uint8_t> bytes = GapBytes(QuicSubheader::CreateAckFrequency(7, 41, 25000, 1));
        NS_TEST_ASSERT_MSG_GT(bytes.size(), 2u, "frame size");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)bytes[0], 0x40u, "first byte of the frame type");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)bytes[1], 0xafu, "second byte of the frame type");
    }
};

/**
 * ACK_ECN (0x03) is an ACK frame with three more counts (RFC 9000 s19.3). It is read, but
 * IsAck() is true only for 0x02, so the receiver does not treat it as an acknowledgement.
 */
class GapAckEcnIsAckTest : public TestCase
{
  public:
    GapAckEcnIsAckTest()
        : TestCase("gap: ACK_ECN is an ACK frame")
    {
    }

  private:
    void DoRun() override
    {
        if (!GapsEnabled("ack-ecn-is-ack"))
        {
            return;
        }
        // largest 5, delay 0, no extra ranges, first range 0, ECT(0), ECT(1) and CE counts of 0
        const uint8_t bytes[] = {0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Buffer buffer;
        buffer.AddAtStart(sizeof(bytes));
        buffer.Begin().Write(bytes, sizeof(bytes));
        QuicSubheader frame;
        frame.Deserialize(buffer.Begin());
        NS_TEST_ASSERT_MSG_EQ(frame.IsAck(), true, "ACK_ECN is an ACK");
    }
};

/**
 * Control for the cases below: a PING in place of the data leaves the connection open (the server
 * acknowledges the packet, so the client does not send the ten bytes again).
 */
class GapControlTest : public TestCase
{
  public:
    GapControlTest()
        : TestCase(
              "gap: control, a rewritten packet that holds a PING does not close the connection")
    {
    }

  private:
    void DoRun() override
    {
        GapScenario scenario({0x01});
        scenario.Run();
        NS_TEST_ASSERT_MSG_EQ(scenario.Injected(), true, "the frame was injected");
        NS_TEST_ASSERT_MSG_EQ(scenario.ServerState(), QuicSocket::OPEN, "server state");
        NS_TEST_ASSERT_MSG_EQ(scenario.ClientState(), QuicSocket::OPEN, "client state");
    }
};

/**
 * A peer that sends ACK_ECN must not lose the connection: the frame is valid (RFC 9000 s19.3.2).
 * The module answers FRAME_ENCODING_ERROR because the receive path has no case for it.
 */
class GapAckEcnConnectionTest : public TestCase
{
  public:
    GapAckEcnConnectionTest()
        : TestCase("gap: a connection survives an ACK_ECN frame")
    {
    }

  private:
    void DoRun() override
    {
        if (!GapsEnabled("ack-ecn-connection"))
        {
            return;
        }
        GapScenario scenario({0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        scenario.Run();
        NS_TEST_ASSERT_MSG_EQ(scenario.Injected(), true, "the frame was injected");
        NS_TEST_ASSERT_MSG_EQ(scenario.ServerState(), QuicSocket::OPEN, "server state");
        NS_TEST_ASSERT_MSG_EQ(scenario.ClientState(), QuicSocket::OPEN, "client state");
    }
};

/**
 * A STREAM frame with the LEN bit and a length of zero ends where its fields end (RFC 9000
 * s19.8). The receiver reads a zero length as "up to the end of the packet", so the PING behind the
 * frame, and the padding, become stream data.
 */
class GapEmptyStreamFrameTest : public TestCase
{
  public:
    GapEmptyStreamFrameTest()
        : TestCase("gap: a STREAM frame of length zero does not swallow the frames behind it")
    {
    }

  private:
    void DoRun() override
    {
        if (!GapsEnabled("empty-stream-frame"))
        {
            return;
        }
        // type 0x0b (LEN and FIN), stream 0, length 0, then a PING
        GapScenario scenario({0x0b, 0x00, 0x00, 0x01});
        scenario.Run();
        NS_TEST_ASSERT_MSG_EQ(scenario.Injected(), true, "the frame was injected");
        NS_TEST_ASSERT_MSG_EQ(scenario.ServerState(), QuicSocket::OPEN, "server state");
        NS_TEST_ASSERT_MSG_EQ(scenario.ServerRx(), 0u, "bytes delivered by an empty stream");
    }
};

/**
 * A frame of a type that RFC 9000 does not define (0x20 here) is a connection error of type
 * FRAME_ENCODING_ERROR. Builds with assertions stop in NS_ASSERT instead, so this case ends the
 * test runner until the parser rejects the type cleanly.
 */
class GapUnknownFrameTypeTest : public TestCase
{
  public:
    GapUnknownFrameTypeTest()
        : TestCase("gap: an undefined frame type closes the connection and nothing more")
    {
    }

  private:
    void DoRun() override
    {
        if (!GapsEnabled("unknown-frame-type"))
        {
            return;
        }
        GapScenario scenario({0x20});
        scenario.Run();
        NS_TEST_ASSERT_MSG_EQ(scenario.Injected(), true, "the frame was injected");
        NS_TEST_ASSERT_MSG_EQ(scenario.ServerState(), QuicSocket::CLOSING, "server state");
    }
};

class QuicGapsTestSuite : public TestSuite
{
  public:
    QuicGapsTestSuite()
        : TestSuite("quic-gaps", Type::UNIT)
    {
        AddTestCase(new GapControlTest, TestCase::Duration::QUICK);
        AddTestCase(new GapAckFrequencyTypeTest, TestCase::Duration::QUICK);
        AddTestCase(new GapAckEcnIsAckTest, TestCase::Duration::QUICK);
        AddTestCase(new GapAckEcnConnectionTest, TestCase::Duration::QUICK);
        AddTestCase(new GapEmptyStreamFrameTest, TestCase::Duration::QUICK);
        AddTestCase(new GapUnknownFrameTypeTest, TestCase::Duration::QUICK);
    }
};

QuicGapsTestSuite g_quicGapsTestSuite;

} // namespace
