/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - handshake suite ("quic-handshake").
 *
 * The emulated TLS 1.3 handshake of RFC 9001: the messages that CRYPTO frames carry, the stream
 * that carries them and, with the sockets, the handshake of a connection.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-crypto-stream.h"
#include "../model/quic-header.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-subheader.h"
#include "../model/quic-tls-emulator.h"
#include "../model/quic-transport-parameters.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <functional>
#include <map>
#include <set>
#include <vector>

using namespace ns3;

namespace
{

/**
 * @return transport parameters like the ones of a connection.
 */
QuicTransportParameters
SomeParameters()
{
    return QuicTransportParameters::CreateTransportParameters(65536, 1 << 20, 4, 30000, 1472, 3, 4);
}

/**
 * The messages of a flight, in order.
 *
 * @param bytes the flight.
 * @return the type and the body size of each message.
 */
std::vector<std::pair<uint8_t, size_t>>
Messages(const std::vector<uint8_t>& bytes)
{
    QuicTlsParser parser;
    parser.Append(bytes);
    std::vector<std::pair<uint8_t, size_t>> out;
    uint8_t type;
    std::vector<uint8_t> body;
    while (parser.Next(type, body))
    {
        out.emplace_back(type, body.size());
    }
    return out;
}

/**
 * The sizes of the messages: the ones that were measured with OpenSSL for a server with one
 * certificate, plus the real parameters and the application protocol in the hello messages.
 */
class TlsSizesTest : public TestCase
{
  public:
    TlsSizesTest()
        : TestCase("sizes of the messages of each profile")
    {
    }

  private:
    void DoRun() override
    {
        const QuicTransportParameters tp = SomeParameters();
        auto ecdsa = Messages(QuicTlsEmulator::ServerFlight(QuicTlsProfile::Ecdsa(), tp, "erlang"));
        NS_TEST_ASSERT_MSG_EQ(ecdsa.size(),
                              4,
                              "EncryptedExtensions, Certificate, CertificateVerify, "
                              "Finished");
        NS_TEST_EXPECT_MSG_EQ(int(ecdsa[0].first), int(TLS_ENCRYPTED_EXTENSIONS), "first");
        NS_TEST_EXPECT_MSG_EQ(ecdsa[1].second, 401, "Certificate of one P-256 certificate");
        NS_TEST_EXPECT_MSG_EQ(ecdsa[2].second, 79, "CertificateVerify");
        NS_TEST_EXPECT_MSG_EQ(ecdsa[3].second, 52, "Finished");

        auto rsa = Messages(QuicTlsEmulator::ServerFlight(QuicTlsProfile::Rsa(), tp, "erlang"));
        NS_TEST_EXPECT_MSG_EQ(rsa[1].second, 798, "Certificate of one RSA 2048 certificate");
        NS_TEST_EXPECT_MSG_EQ(rsa[2].second, 264, "CertificateVerify");

        QuicTlsProfile chain = QuicTlsProfile::Ecdsa();
        chain.chainLength = 3;
        auto three = Messages(QuicTlsEmulator::ServerFlight(chain, tp, "erlang"));
        NS_TEST_EXPECT_MSG_EQ(three[1].second, 1 + 3 + 3 * (3 + 392 + 2), "three certificates");

        QuicTlsProfile mtls;
        NS_TEST_ASSERT_MSG_EQ(QuicTlsProfile::FromName("ecdsa+mtls", mtls), true, "name");
        auto asked = Messages(QuicTlsEmulator::ServerFlight(mtls, tp, "erlang"));
        NS_TEST_EXPECT_MSG_EQ(asked.size(), 5, "a CertificateRequest too");
        NS_TEST_EXPECT_MSG_EQ(int(asked[1].first), int(TLS_CERTIFICATE_REQUEST), "second");
        auto client = Messages(QuicTlsEmulator::ClientFlight(mtls));
        NS_TEST_EXPECT_MSG_EQ(client.size(), 3, "Certificate, CertificateVerify and Finished");
        auto plain = Messages(QuicTlsEmulator::ClientFlight(QuicTlsProfile::Ecdsa()));
        NS_TEST_EXPECT_MSG_EQ(plain.size(), 1, "Finished only");
        NS_TEST_EXPECT_MSG_EQ(plain[0].second, 52, "Finished");
        NS_TEST_EXPECT_MSG_EQ(QuicTlsProfile::FromName("des", mtls), false, "unknown name");

        auto hello = Messages(QuicTlsEmulator::ServerHello(QuicTlsProfile::Ecdsa()));
        NS_TEST_EXPECT_MSG_EQ(hello[0].second, 90, "ServerHello without a session id");
        const auto ch =
            QuicTlsEmulator::ClientHello(QuicTlsProfile::Ecdsa(), tp, {"erlang"}, false);
        NS_TEST_EXPECT_MSG_GT(ch.size(), 280, "a ClientHello of a few hundred bytes");
        NS_TEST_EXPECT_MSG_LT(ch.size(), 420, "and not more");

        const auto pq =
            QuicTlsEmulator::ClientHello(QuicTlsProfile::PqHybrid(), tp, {"erlang"}, false);
        NS_TEST_EXPECT_MSG_GT(pq.size(),
                              1400,
                              "the post-quantum key share does not fit in one packet");
        auto pqHello = Messages(QuicTlsEmulator::ServerHello(QuicTlsProfile::PqHybrid()));
        NS_TEST_EXPECT_MSG_GT(pqHello[0].second, 1100, "and the answer is large");
    }
};

/**
 * What the hello messages carry: the transport parameters and the protocol names come back out.
 */
class TlsExtensionsTest : public TestCase
{
  public:
    TlsExtensionsTest()
        : TestCase("extensions of the hello messages")
    {
    }

  private:
    void DoRun() override
    {
        const QuicTransportParameters tp = SomeParameters();
        for (bool pq : {false, true})
        {
            const auto profile = pq ? QuicTlsProfile::PqHybrid() : QuicTlsProfile::Ecdsa();
            QuicTlsParser parser;
            parser.Append(QuicTlsEmulator::ClientHello(profile, tp, {"erlang", "h3"}, false));
            uint8_t type;
            std::vector<uint8_t> body;
            NS_TEST_ASSERT_MSG_EQ(parser.Next(type, body), true, "a message");
            NS_TEST_ASSERT_MSG_EQ(int(type), int(TLS_CLIENT_HELLO), "ClientHello");
            std::vector<uint8_t> data;
            NS_TEST_ASSERT_MSG_EQ(
                QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_TRANSPORT_PARAMETERS, data),
                true,
                "transport parameters");
            QuicTransportParameters back;
            NS_TEST_ASSERT_MSG_EQ(QuicTlsParser::ParseTransportParameters(data, back),
                                  true,
                                  "valid");
            NS_TEST_EXPECT_MSG_EQ((back == tp), true, "the same parameters");
            NS_TEST_ASSERT_MSG_EQ(QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_ALPN, data),
                                  true,
                                  "ALPN");
            std::vector<std::string> names;
            NS_TEST_ASSERT_MSG_EQ(QuicTlsParser::ParseAlpn(data, names), true, "well formed");
            NS_TEST_EXPECT_MSG_EQ(names.size(), 2, "two names");
            NS_TEST_EXPECT_MSG_EQ(names[0], "erlang", "first");
            NS_TEST_EXPECT_MSG_EQ(QuicTlsParser::FindExtension(type, body, 0x7777, data),
                                  false,
                                  "an extension that is not there");

            // a message that is cut anywhere is refused, never read past its end
            for (size_t cut = 0; cut + 1 < body.size(); cut += 7)
            {
                std::vector<uint8_t> shorter(body.begin(), body.begin() + cut);
                QuicTlsParser::FindExtension(type, shorter, QUIC_TLS_EXT_ALPN, data);
            }
        }

        // EncryptedExtensions carries the parameters of the server and the chosen protocol
        QuicTlsParser server;
        server.Append(QuicTlsEmulator::ServerFlight(QuicTlsProfile::Ecdsa(), tp, "erlang"));
        uint8_t type;
        std::vector<uint8_t> body;
        NS_TEST_ASSERT_MSG_EQ(server.Next(type, body), true, "EncryptedExtensions");
        std::vector<uint8_t> data;
        NS_TEST_EXPECT_MSG_EQ(QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_ALPN, data),
                              true,
                              "ALPN");
        std::vector<std::string> names;
        NS_TEST_EXPECT_MSG_EQ(QuicTlsParser::ParseAlpn(data, names), true, "well formed");
        NS_TEST_EXPECT_MSG_EQ(names[0], "erlang", "chosen");
        NS_TEST_EXPECT_MSG_EQ(
            QuicTlsParser::FindExtension(type, body, QUIC_TLS_EXT_TRANSPORT_PARAMETERS, data),
            true,
            "parameters");
    }
};

/**
 * The parser puts messages together from pieces of any size.
 */
class TlsParserTest : public TestCase
{
  public:
    TlsParserTest()
        : TestCase("messages put together from pieces")
    {
    }

  private:
    void DoRun() override
    {
        const auto flight =
            QuicTlsEmulator::ServerFlight(QuicTlsProfile::Rsa(), SomeParameters(), "erlang");
        const auto expected = Messages(flight);
        for (size_t piece : {1u, 7u, 100u, 1200u})
        {
            QuicTlsParser parser;
            std::vector<std::pair<uint8_t, size_t>> got;
            for (size_t at = 0; at < flight.size(); at += piece)
            {
                parser.Append(
                    std::vector<uint8_t>(flight.begin() + at,
                                         flight.begin() + std::min(flight.size(), at + piece)));
                uint8_t type;
                std::vector<uint8_t> body;
                while (parser.Next(type, body))
                {
                    got.emplace_back(type, body.size());
                }
            }
            NS_TEST_EXPECT_MSG_EQ((got == expected), true, "pieces of " << piece);
        }
    }
};

/**
 * The CRYPTO stream: sending with loss and acknowledgment, receiving out of order.
 */
class CryptoStreamTest : public TestCase
{
  public:
    CryptoStreamTest()
        : TestCase("the CRYPTO stream")
    {
    }

  private:
    void DoRun() override
    {
        QuicCryptoStream tx;
        std::vector<uint8_t> flight(2500);
        for (size_t k = 0; k < flight.size(); ++k)
        {
            flight[k] = static_cast<uint8_t>(k * 7);
        }
        tx.Queue(flight);
        uint64_t offset;
        std::vector<uint8_t> data;
        NS_TEST_ASSERT_MSG_EQ(tx.NextChunk(1000, offset, data), true, "first chunk");
        NS_TEST_EXPECT_MSG_EQ(offset, 0, "at the start");
        NS_TEST_EXPECT_MSG_EQ(data.size(), 1000, "the size asked");
        NS_TEST_ASSERT_MSG_EQ(tx.NextChunk(1000, offset, data), true, "second chunk");
        NS_TEST_EXPECT_MSG_EQ(offset, 1000, "next");
        tx.OnLost(1000, 1000);
        NS_TEST_ASSERT_MSG_EQ(tx.NextChunk(600, offset, data), true, "the lost range first");
        NS_TEST_EXPECT_MSG_EQ(offset, 1000, "again from 1000");
        NS_TEST_EXPECT_MSG_EQ(data.size(), 600, "a part of it");
        NS_TEST_ASSERT_MSG_EQ(tx.NextChunk(600, offset, data), true, "the rest of it");
        NS_TEST_EXPECT_MSG_EQ(offset, 1600, "continues");
        NS_TEST_EXPECT_MSG_EQ(data.size(), 400, "what was left");
        NS_TEST_ASSERT_MSG_EQ(tx.NextChunk(1000, offset, data), true, "new data");
        NS_TEST_EXPECT_MSG_EQ(offset, 2000, "after what was sent");
        NS_TEST_EXPECT_MSG_EQ(data.size(), 500, "the end");
        NS_TEST_EXPECT_MSG_EQ(tx.HasDataToSend(), false, "all sent");
        tx.OnAcked(0, 1000);
        tx.OnLost(0, 1000); // acknowledged in the meantime: not sent again
        NS_TEST_EXPECT_MSG_EQ(tx.HasDataToSend(), false, "an acknowledged range is not resent");
        NS_TEST_EXPECT_MSG_EQ(tx.AllAcked(), false, "not everything is acknowledged");
        tx.OnAcked(1000, 1500);
        NS_TEST_EXPECT_MSG_EQ(tx.AllAcked(), true, "everything is");

        QuicCryptoStream rx;
        NS_TEST_ASSERT_MSG_EQ(
            rx.OnFrame(1000, {flight.begin() + 1000, flight.begin() + 2000}, 4096),
            true,
            "out of order");
        NS_TEST_EXPECT_MSG_EQ(rx.Read().size(), 0, "nothing in order yet");
        NS_TEST_ASSERT_MSG_EQ(rx.OnFrame(0, {flight.begin(), flight.begin() + 1200}, 4096),
                              true,
                              "the start, overlapping");
        std::vector<uint8_t> got = rx.Read();
        NS_TEST_EXPECT_MSG_EQ(got.size(), 2000, "both pieces");
        NS_TEST_EXPECT_MSG_EQ((got == std::vector<uint8_t>(flight.begin(), flight.begin() + 2000)),
                              true,
                              "the same bytes");
        NS_TEST_ASSERT_MSG_EQ(rx.OnFrame(500, {flight.begin() + 500, flight.begin() + 900}, 4096),
                              true,
                              "a repeat");
        NS_TEST_EXPECT_MSG_EQ(rx.Read().size(), 0, "ignored");
        NS_TEST_EXPECT_MSG_EQ(rx.ReceivedOffset(), 2000, "offset");
        NS_TEST_EXPECT_MSG_EQ(rx.OnFrame(4000, std::vector<uint8_t>(200), 4096),
                              false,
                              "beyond the limit of the buffer");
    }
};

/** What a test sees of a packet that one end sent or received. */
struct SeenPacket
{
    Time time;                   //!< when
    std::string type;            //!< "initial", "handshake", "0rtt" or "1rtt"
    uint64_t number{0};          //!< packet number
    uint64_t cryptoBytes{0};     //!< bytes of CRYPTO data
    uint64_t cryptoStart{0};     //!< offset of the first CRYPTO frame, when there is one
    bool hasCrypto{false};       //!< the packet has a CRYPTO frame
    bool ackOnly{false};         //!< the packet has only ACK and PADDING frames
    size_t tokenBytes{0};        //!< bytes of the token of an Initial or Retry packet
    bool newToken{false};        //!< the packet has a NEW_TOKEN frame
    bool keyPhase{false};        //!< the Key Phase bit of a 1-RTT packet
    bool connectionClose{false}; //!< the packet has a CONNECTION_CLOSE frame
    uint64_t closeCode{0};       //!< the error code of that frame
};

/**
 * @param p the frames of a packet.
 * @param h its header.
 * @return what the frames say.
 */
SeenPacket
Describe(Ptr<const Packet> p, const QuicHeader& h)
{
    SeenPacket seen;
    seen.time = Simulator::Now();
    seen.type = h.IsInitial()     ? "initial"
                : h.IsHandshake() ? "handshake"
                : h.IsORTT()      ? "0rtt"
                : h.IsRetry()     ? "retry"
                                  : "1rtt";
    seen.tokenBytes = (h.IsInitial() || h.IsRetry()) ? h.GetToken().size() : 0;
    seen.keyPhase = h.IsShort() && h.GetKeyPhaseBit();
    seen.number = h.HasPacketNumber() ? h.GetPacketNumber().GetValue() : 0;
    seen.ackOnly = true;
    Ptr<Packet> rest = p->Copy();
    while (rest->GetSize() > 0)
    {
        QuicSubheader sub;
        rest->RemoveHeader(sub);
        if (!sub.IsValid())
        {
            break;
        }
        const uint64_t length =
            std::min<uint64_t>(sub.GetPayloadLength(rest->GetSize()), rest->GetSize());
        rest->RemoveAtStart(length);
        if (sub.IsCrypto())
        {
            if (!seen.hasCrypto)
            {
                seen.cryptoStart = sub.GetOffset();
            }
            seen.hasCrypto = true;
            seen.cryptoBytes += length;
        }
        if (sub.IsNewToken())
        {
            seen.newToken = true;
        }
        if (sub.IsConnectionClose())
        {
            seen.connectionClose = true;
            seen.closeCode = sub.GetErrorCode();
        }
        if (!sub.IsAck() && !sub.IsPadding())
        {
            seen.ackOnly = false;
        }
    }
    return seen;
}

/**
 * Two nodes with a connection that is being made, and what each end sent and received.
 */
class HsRig
{
  public:
    std::string serverProfile{"ecdsa"}; //!< TlsProfile of both ends
    uint32_t chainLength{1};            //!< CertificateChainLength of the server
    std::string clientAlpn{"erlang"};   //!< Alpn of the client
    std::string serverAlpn{"erlang"};   //!< Alpn of the server
    std::string rate{"10Mbps"};         //!< rate of the link
    std::string delay{"10ms"};          //!< delay of the link
    Time stopAt{Seconds(5)};            //!< when the simulation ends
    std::function<void(Ptr<NetDevice> server, Ptr<NetDevice> client)> onBuilt; //!< hook for losses

    std::vector<SeenPacket> clientTx;                  //!< packets the client sent
    std::vector<SeenPacket> clientRx;                  //!< packets the client received
    std::vector<SeenPacket> serverTx;                  //!< packets the server sent
    std::vector<SeenPacket> serverRx;                  //!< packets the server received
    std::vector<std::pair<Time, uint32_t>> clientWire; //!< UDP payloads the client sent
    std::vector<std::pair<Time, uint32_t>> serverWire; //!< UDP payloads the server sent
    bool retry{false};                //!< the server answers the first Initial with a Retry
    uint32_t keyUpdatePackets{0};     //!< KeyUpdatePackets of both ends
    uint64_t clientSends{0};          //!< bytes the client writes once connected
    Time secondConnectAt{Seconds(0)}; //!< when a second client connects, none when zero
    std::vector<SeenPacket> secondTx; //!< packets the second client sent
    std::vector<SeenPacket> secondRx; //!< packets the second client received
    bool secondConnected{false};      //!< the second client connected
    bool connected{false};            //!< the connect callback of the client said success
    bool failed{false};               //!< ... or failure
    Ptr<QuicSocketBase> client;       //!< the client socket
    Ptr<QuicSocketBase> server;       //!< the socket of the accepted connection
    uint64_t serverRxBytes{0};        //!< bytes the server application read

    /** Run the scenario. */
    void Run()
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue(rate));
        link.SetChannelAttribute("Delay", StringValue(delay));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        nodes.Get(0)->GetObject<QuicL4Protocol>()->SetAttribute("RetryEnabled",
                                                                BooleanValue(retry));
        Ipv4AddressHelper address;
        address.SetBase("10.5.4.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        devices.Get(0)->TraceConnectWithoutContext("PhyTxEnd",
                                                   MakeCallback(&HsRig::OnServerPhy, this));
        devices.Get(1)->TraceConnectWithoutContext("PhyTxEnd",
                                                   MakeCallback(&HsRig::OnClientPhy, this));
        if (onBuilt)
        {
            onBuilt(devices.Get(0), devices.Get(1));
        }

        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->SetAttribute("TlsProfile", StringValue(serverProfile));
        listener->SetAttribute("CertificateChainLength", UintegerValue(chainLength));
        listener->SetAttribute("Alpn", StringValue(serverAlpn));
        listener->SetAttribute("KeyUpdatePackets", UintegerValue(keyUpdatePackets));
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&HsRig::Accepted, this));
        Ptr<QuicSocketBase> lq = DynamicCast<QuicSocketBase>(listener);
        lq->TraceConnectWithoutContext("Tx", MakeCallback(&HsRig::OnServerTx, this));
        lq->TraceConnectWithoutContext("Rx", MakeCallback(&HsRig::OnServerRx, this));

        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        socket->SetAttribute("TlsProfile", StringValue(serverProfile));
        socket->SetAttribute("Alpn", StringValue(clientAlpn));
        socket->SetAttribute("KeyUpdatePackets", UintegerValue(keyUpdatePackets));
        client = DynamicCast<QuicSocketBase>(socket);
        client->TraceConnectWithoutContext("Tx", MakeCallback(&HsRig::OnClientTx, this));
        client->TraceConnectWithoutContext("Rx", MakeCallback(&HsRig::OnClientRx, this));
        socket->SetConnectCallback(MakeCallback(&HsRig::OnConnected, this),
                                   MakeCallback(&HsRig::OnFailed, this));
        Simulator::Schedule(Seconds(0.1), [socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        if (clientSends > 0)
        {
            Simulator::Schedule(Seconds(0.5),
                                [this]() { client->Send(Create<Packet>(clientSends)); });
        }
        if (secondConnectAt.IsStrictlyPositive())
        {
            Simulator::Schedule(secondConnectAt, [this, nodes, interfaces, factory]() {
                Ptr<Socket> second = Socket::CreateSocket(nodes.Get(1), factory);
                Ptr<QuicSocketBase> q = DynamicCast<QuicSocketBase>(second);
                q->TraceConnectWithoutContext("Tx", MakeCallback(&HsRig::OnSecondTx, this));
                q->TraceConnectWithoutContext("Rx", MakeCallback(&HsRig::OnSecondRx, this));
                second->SetConnectCallback(MakeCallback(&HsRig::OnSecondConnected, this),
                                           MakeNullCallback<void, Ptr<Socket>>());
                m_second = second;
                second->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
            });
        }
        Simulator::Stop(stopAt);
        Simulator::Run();
        Simulator::Destroy();
    }

    /**
     * @param packets some packets.
     * @param type a packet type.
     * @return how many of them have the type.
     */
    static size_t CountOf(const std::vector<SeenPacket>& packets, const std::string& type)
    {
        size_t n = 0;
        for (const auto& p : packets)
        {
            n += p.type == type ? 1 : 0;
        }
        return n;
    }

    /**
     * @param packets some packets.
     * @param type a packet type.
     * @return the bytes of CRYPTO data they carry at that level, counted once.
     */
    static uint64_t CryptoOf(const std::vector<SeenPacket>& packets, const std::string& type)
    {
        std::map<uint64_t, uint64_t> byOffset;
        for (const auto& p : packets)
        {
            if (p.type == type && p.hasCrypto)
            {
                byOffset[p.cryptoStart] = std::max(byOffset[p.cryptoStart], p.cryptoBytes);
            }
        }
        uint64_t total = 0;
        for (const auto& entry : byOffset)
        {
            total += entry.second;
        }
        return total;
    }

  private:
    void Accepted(Ptr<Socket> socket, const Address&)
    {
        server = DynamicCast<QuicSocketBase>(socket);
        socket->SetRecvCallback(MakeCallback(&HsRig::ServerRead, this));
    }

    void ServerRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            serverRxBytes += packet->GetSize();
        }
    }

    void OnConnected(Ptr<Socket>)
    {
        connected = true;
    }

    void OnFailed(Ptr<Socket>)
    {
        failed = true;
    }

    void OnClientTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        clientTx.push_back(Describe(p, h));
    }

    void OnClientRx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        clientRx.push_back(Describe(p, h));
    }

    void OnServerTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        serverTx.push_back(Describe(p, h));
    }

    void OnServerRx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        serverRx.push_back(Describe(p, h));
    }

    void OnSecondTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        secondTx.push_back(Describe(p, h));
    }

    void OnSecondRx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        secondRx.push_back(Describe(p, h));
    }

    void OnSecondConnected(Ptr<Socket>)
    {
        secondConnected = true;
    }

    Ptr<Socket> m_second; //!< the second client

    void OnClientPhy(Ptr<const Packet> p)
    {
        clientWire.emplace_back(Simulator::Now(), p->GetSize() - 2 - 20 - 8);
    }

    void OnServerPhy(Ptr<const Packet> p)
    {
        serverWire.emplace_back(Simulator::Now(), p->GetSize() - 2 - 20 - 8);
    }
};

/**
 * The first flights of a handshake: the ClientHello in an Initial packet in a datagram of 1200
 * bytes, the server answering with an Initial and a Handshake packet in one datagram, each level
 * with its own packet numbers, the client's Finished and HANDSHAKE_DONE.
 */
class HandshakeFlightsTest : public TestCase
{
  public:
    HandshakeFlightsTest()
        : TestCase("the flights of a handshake")
    {
    }

  private:
    void DoRun() override
    {
        HsRig rig;
        rig.Run();
        NS_TEST_ASSERT_MSG_EQ(rig.connected, true, "the client connected");
        NS_TEST_ASSERT_MSG_NE(rig.server, nullptr, "the server accepted");
        NS_TEST_ASSERT_MSG_EQ(rig.client->GetSocketState(), QuicSocket::OPEN, "open");
        NS_TEST_ASSERT_MSG_EQ(rig.server->GetSocketState(), QuicSocket::OPEN, "open");

        NS_TEST_ASSERT_MSG_GT(rig.clientTx.size(), 2, "the client sent packets");
        NS_TEST_EXPECT_MSG_EQ(rig.clientTx[0].type, "initial", "the first packet is an Initial");
        NS_TEST_EXPECT_MSG_EQ(rig.clientTx[0].hasCrypto, true, "with the ClientHello");
        NS_TEST_EXPECT_MSG_GT(rig.clientTx[0].cryptoBytes, 280, "of a few hundred bytes");
        NS_TEST_EXPECT_MSG_GT(rig.clientWire[0].second, 1199, "in a datagram of 1200 bytes");

        // the server answers with the ServerHello and the rest of its flight together
        NS_TEST_ASSERT_MSG_GT(rig.serverTx.size(), 1, "the server answered");
        NS_TEST_EXPECT_MSG_EQ(rig.serverTx[0].type, "initial", "ServerHello first");
        NS_TEST_EXPECT_MSG_EQ(rig.serverTx[1].type, "handshake", "then the rest");
        NS_TEST_EXPECT_MSG_EQ(rig.serverTx[0].time == rig.serverTx[1].time, true, "at once");
        NS_TEST_EXPECT_MSG_EQ(rig.serverTx[0].number, 0, "Initial space starts at 0");
        NS_TEST_EXPECT_MSG_EQ(rig.serverTx[1].number, 0, "Handshake space starts at 0");
        NS_TEST_EXPECT_MSG_GT(rig.serverWire[0].second, 1199, "the datagram has 1200 bytes");
        NS_TEST_EXPECT_MSG_EQ(HsRig::CryptoOf(rig.serverTx, "initial"),
                              QuicTlsEmulator::ServerHello(QuicTlsProfile::Ecdsa()).size(),
                              "the ServerHello");

        // the client finishes in a Handshake packet, and the server confirms in a 1-RTT packet
        NS_TEST_EXPECT_MSG_EQ(HsRig::CryptoOf(rig.clientTx, "handshake"),
                              QuicTlsEmulator::ClientFlight(QuicTlsProfile::Ecdsa()).size(),
                              "the Finished of the client");
        NS_TEST_EXPECT_MSG_GT(HsRig::CountOf(rig.serverTx, "1rtt"), 0, "HANDSHAKE_DONE");

        // after the handshake nothing is sent at the Initial or Handshake level
        const Time done = rig.clientTx.back().time;
        NS_TEST_EXPECT_MSG_GT(done, Seconds(0.1), "time moves");
        size_t late = 0;
        for (const auto& p : rig.clientTx)
        {
            late += (p.time > Seconds(2) && (p.type == "initial" || p.type == "handshake")) ? 1 : 0;
        }
        for (const auto& p : rig.serverTx)
        {
            late += (p.time > Seconds(2) && (p.type == "initial" || p.type == "handshake")) ? 1 : 0;
        }
        NS_TEST_EXPECT_MSG_EQ(late, 0, "the keys of the handshake levels are gone");
    }
};

/**
 * The profiles change what the server sends, and the handshake still completes.
 */
class HandshakeProfilesTest : public TestCase
{
  public:
    HandshakeProfilesTest()
        : TestCase("profiles of the handshake")
    {
    }

  private:
    void DoRun() override
    {
        for (const std::string name : {"ecdsa", "rsa", "rsa+mtls", "pq-hybrid"})
        {
            QuicTlsProfile profile;
            NS_TEST_ASSERT_MSG_EQ(QuicTlsProfile::FromName(name, profile), true, name);
            HsRig rig;
            rig.serverProfile = name;
            rig.Run();
            NS_TEST_EXPECT_MSG_EQ(rig.connected, true, name << " connected");
            const uint64_t flight =
                QuicTlsEmulator::ServerFlight(
                    profile,
                    QuicTransportParameters::CreateTransportParameters(1, 1, 1, 1, 1472, 3, 1),
                    "erlang")
                    .size();
            const uint64_t hello = QuicTlsEmulator::ServerHello(profile).size();
            // the flight has the parameters of the connection, a few bytes more than the plain ones
            NS_TEST_EXPECT_MSG_GT(HsRig::CryptoOf(rig.serverTx, "handshake"), flight - 40, name);
            NS_TEST_EXPECT_MSG_LT(HsRig::CryptoOf(rig.serverTx, "handshake"), flight + 120, name);
            NS_TEST_EXPECT_MSG_EQ(HsRig::CryptoOf(rig.serverTx, "initial"), hello, name);
            NS_TEST_EXPECT_MSG_EQ(HsRig::CryptoOf(rig.clientTx, "handshake"),
                                  QuicTlsEmulator::ClientFlight(profile).size(),
                                  name << " client flight");
            if (name == "pq-hybrid")
            {
                NS_TEST_EXPECT_MSG_GT(HsRig::CountOf(rig.clientTx, "initial"),
                                      2,
                                      "the ClientHello needs two Initial packets, and an ACK");
                NS_TEST_EXPECT_MSG_GT(HsRig::CryptoOf(rig.clientTx, "initial"), 1400, name);
            }
        }
    }
};

/**
 * A long certificate chain does not go out faster than three times what the client sent, until
 * the client has answered (RFC 9000, Section 8.1).
 */
class HandshakeAmplificationTest : public TestCase
{
  public:
    HandshakeAmplificationTest()
        : TestCase("the server stays within three times what it received")
    {
    }

  private:
    void DoRun() override
    {
        HsRig rig;
        rig.chainLength = 8; // about 3.5 KB of certificates: more than three Initial datagrams
        rig.Run();
        NS_TEST_ASSERT_MSG_EQ(rig.connected, true, "the connection comes up in the end");
        // what the server sent before it heard anything more than the first datagram
        const Time second = [&rig]() {
            for (size_t k = 1; k < rig.clientWire.size(); ++k)
            {
                // the client's second datagram arrives at the server one delay later
                return rig.clientWire[k].first + MilliSeconds(10);
            }
            return Seconds(100);
        }();
        uint64_t before = 0;
        for (const auto& d : rig.serverWire)
        {
            if (d.first < second)
            {
                before += d.second;
            }
        }
        NS_TEST_EXPECT_MSG_LT(before, 3 * 1200 + 1, "three datagrams of the client's size at most");
        NS_TEST_EXPECT_MSG_GT(rig.serverWire.size(), 3, "the flight needed more datagrams");
    }
};

/**
 * The server's first flight is lost: the client sends its Initial again, the server repeats the
 * flight and the handshake completes.
 */
class HandshakeServerLossTest : public TestCase
{
  public:
    HandshakeServerLossTest()
        : TestCase("a lost server flight is sent again")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<ListErrorModel> loss = CreateObject<ListErrorModel>();
        HsRig rig;
        rig.onBuilt = [loss](Ptr<NetDevice>, Ptr<NetDevice> client) {
            // the first datagram that reaches the client, the server flight, is lost
            loss->SetList({0});
            client->SetAttribute("ReceiveErrorModel", PointerValue(loss));
        };
        rig.stopAt = Seconds(10);
        rig.Run();
        NS_TEST_ASSERT_MSG_EQ(rig.connected, true, "the connection comes up");
        NS_TEST_EXPECT_MSG_GT(HsRig::CountOf(rig.clientTx, "initial"),
                              1,
                              "the Initial was sent again");
        NS_TEST_EXPECT_MSG_GT(HsRig::CountOf(rig.serverTx, "handshake"), 1, "so was the flight");
        // the packet numbers do not repeat in a space
        std::set<uint64_t> numbers;
        for (const auto& p : rig.serverTx)
        {
            if (p.type == "handshake")
            {
                NS_TEST_EXPECT_MSG_EQ(numbers.insert(p.number).second, true, "a new number");
            }
        }
    }
};

/**
 * RFC 9000, Section 8.1.2: the server answers the first Initial packet with a Retry packet that
 * carries a token, the client sends its Initial again with the token, and the connection costs
 * a round trip more. The connection ids of the Retry are checked through the transport
 * parameters (Section 7.3). After the handshake the server gives the client a token in a NEW_TOKEN
 * frame, and the next connection of that client needs no Retry (Section 8.1.3).
 */
class HandshakeRetryTest : public TestCase
{
  public:
    HandshakeRetryTest()
        : TestCase("Retry, and NEW_TOKEN to avoid it")
    {
    }

  private:
    void DoRun() override
    {
        HsRig plain;
        plain.Run();
        NS_TEST_ASSERT_MSG_EQ(plain.connected, true, "without Retry");
        NS_TEST_EXPECT_MSG_EQ(HsRig::CountOf(plain.clientRx, "retry"), 0, "no Retry");

        HsRig rig;
        rig.retry = true;
        rig.secondConnectAt = Seconds(2);
        rig.stopAt = Seconds(6);
        rig.Run();
        NS_TEST_ASSERT_MSG_EQ(rig.connected, true, "the connection comes up after a Retry");
        NS_TEST_EXPECT_MSG_EQ(HsRig::CountOf(rig.clientRx, "retry"), 1, "one Retry packet");
        NS_TEST_ASSERT_MSG_GT(rig.clientRx.size(), 0, "packets");
        NS_TEST_EXPECT_MSG_GT(rig.clientRx[0].tokenBytes, 0, "with a token");
        NS_TEST_ASSERT_MSG_GT(HsRig::CountOf(rig.clientTx, "initial"),
                              1,
                              "the Initial is sent again");
        NS_TEST_EXPECT_MSG_EQ(rig.clientTx[0].tokenBytes, 0, "the first one has no token");
        size_t withToken = 0;
        for (const auto& p : rig.clientTx)
        {
            withToken += (p.type == "initial" && p.tokenBytes > 0 && p.hasCrypto) ? 1 : 0;
        }
        NS_TEST_EXPECT_MSG_GT(withToken, 0, "the second one carries the token");
        // the handshake is one round trip later than without Retry
        Time plainDone;
        Time retryDone;
        for (const auto& p : plain.clientTx)
        {
            if (p.type == "handshake")
            {
                plainDone = p.time;
                break;
            }
        }
        for (const auto& p : rig.clientTx)
        {
            if (p.type == "handshake")
            {
                retryDone = p.time;
                break;
            }
        }
        NS_TEST_EXPECT_MSG_GT(retryDone - plainDone,
                              MilliSeconds(18),
                              "a round trip of 20 ms more");

        // the server sent a NEW_TOKEN frame, and the second connection used it
        bool gotToken = false;
        for (const auto& p : rig.clientRx)
        {
            gotToken = gotToken || p.newToken;
        }
        NS_TEST_EXPECT_MSG_EQ(gotToken, true, "NEW_TOKEN");
        NS_TEST_ASSERT_MSG_EQ(rig.secondConnected, true, "the second connection comes up");
        NS_TEST_EXPECT_MSG_EQ(HsRig::CountOf(rig.secondRx, "retry"), 0, "no Retry the second time");
        NS_TEST_ASSERT_MSG_GT(rig.secondTx.size(), 0, "packets");
        NS_TEST_EXPECT_MSG_GT(rig.secondTx[0].tokenBytes, 0, "its first Initial has the token");
    }
};

/**
 * RFC 9001, Section 6: the keys of the 1-RTT packets are updated, which shows in the Key Phase bit.
 * The data keeps flowing in both directions, and the phase that each end sends changes more than
 * once, each time after a packet with the old keys was acknowledged.
 */
class HandshakeKeyUpdateTest : public TestCase
{
  public:
    HandshakeKeyUpdateTest()
        : TestCase("key update changes the Key Phase bit")
    {
    }

  private:
    void DoRun() override
    {
        HsRig off;
        off.clientSends = 200000;
        off.Run();
        for (const auto& p : off.clientTx)
        {
            NS_TEST_EXPECT_MSG_EQ(p.keyPhase, false, "without updates the phase stays 0");
        }

        HsRig rig;
        rig.keyUpdatePackets = 30;
        rig.clientSends = 200000;
        rig.Run();
        NS_TEST_EXPECT_MSG_EQ(rig.serverRxBytes, 200000, "the data arrives across key updates");
        auto changes = [](const std::vector<SeenPacket>& packets) {
            size_t n = 0;
            bool last = false;
            for (const auto& p : packets)
            {
                if (p.type == "1rtt")
                {
                    n += p.keyPhase != last ? 1 : 0;
                    last = p.keyPhase;
                }
            }
            return n;
        };
        NS_TEST_EXPECT_MSG_GT(changes(rig.clientTx), 2, "the client changed its phase");
        NS_TEST_EXPECT_MSG_GT(changes(rig.serverTx), 1, "and the server followed or started");
    }
};

/**
 * Endpoints that share no application protocol fail with the TLS alert no_application_protocol
 * (RFC 9001, Section 8.1).
 */
class HandshakeAlpnTest : public TestCase
{
  public:
    HandshakeAlpnTest()
        : TestCase("no application protocol in common")
    {
    }

  private:
    void DoRun() override
    {
        HsRig rig;
        rig.clientAlpn = "h3";
        rig.serverAlpn = "erlang";
        rig.Run();
        NS_TEST_EXPECT_MSG_EQ(rig.connected, false, "no connection");
        bool closed = false;
        for (const auto& p : rig.serverTx)
        {
            if (p.connectionClose)
            {
                closed = true;
                NS_TEST_EXPECT_MSG_EQ(p.closeCode, 0x178, "no_application_protocol");
            }
        }
        NS_TEST_EXPECT_MSG_EQ(closed, true, "the server closed the connection");

        // the client offers two protocols and the server takes the first one it knows
        HsRig two;
        two.clientAlpn = "h3,erlang";
        two.serverAlpn = "erlang,other";
        two.Run();
        NS_TEST_EXPECT_MSG_EQ(two.connected, true, "a common protocol is chosen");
    }
};

class QuicHandshakeTestSuite : public TestSuite
{
  public:
    QuicHandshakeTestSuite()
        : TestSuite("quic-handshake", Type::UNIT)
    {
        AddTestCase(new TlsSizesTest, TestCase::Duration::QUICK);
        AddTestCase(new TlsExtensionsTest, TestCase::Duration::QUICK);
        AddTestCase(new TlsParserTest, TestCase::Duration::QUICK);
        AddTestCase(new CryptoStreamTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeFlightsTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeProfilesTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeAmplificationTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeServerLossTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeAlpnTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeRetryTest, TestCase::Duration::QUICK);
        AddTestCase(new HandshakeKeyUpdateTest, TestCase::Duration::QUICK);
    }
};

QuicHandshakeTestSuite g_quicHandshakeTestSuite;

} // namespace
