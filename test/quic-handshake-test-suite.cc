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

#include "../model/quic-crypto-stream.h"
#include "../model/quic-tls-emulator.h"
#include "../model/quic-transport-parameters.h"

#include "ns3/core-module.h"
#include "ns3/test.h"

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
    }
};

QuicHandshakeTestSuite g_quicHandshakeTestSuite;

} // namespace
