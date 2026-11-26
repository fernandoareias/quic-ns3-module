/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - frame suite ("quic-frames").
 *
 * The frames of RFC 9000, Section 19 and the frames of the extensions the module speaks, byte by
 * byte, and what a receiver does with frames that are not valid (RFC 9000, Section 12.4): a frame
 * that is truncated, of an unknown type or not in its shortest form is never read past, and ends
 * the connection with the error code of the RFC instead of stopping the simulator.
 */

#include "../model/quic-header.h"
#include "../model/quic-subheader.h"
#include "quic-injection.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <random>
#include <string>
#include <vector>

using namespace ns3;
using namespace quic_test;

namespace
{

/**
 * Serialize a frame.
 *
 * @param frame the frame.
 * @return its bytes.
 */
std::vector<uint8_t>
FrameBytes(const QuicSubheader& frame)
{
    Buffer buffer;
    buffer.AddAtStart(frame.GetSerializedSize());
    frame.Serialize(buffer.Begin());
    std::vector<uint8_t> bytes(buffer.GetSize());
    buffer.CopyData(bytes.data(), bytes.size());
    return bytes;
}

/**
 * Read a frame from bytes.
 *
 * @param bytes the bytes.
 * @param frame set to the frame read.
 * @return the number of bytes the frame used.
 */
uint32_t
ReadFrame(const std::vector<uint8_t>& bytes, QuicSubheader& frame)
{
    Buffer buffer;
    buffer.AddAtStart(bytes.size());
    if (!bytes.empty())
    {
        buffer.Begin().Write(bytes.data(), bytes.size());
    }
    return frame.Deserialize(buffer.Begin());
}

/**
 * Parse a string of hexadecimal digits.
 *
 * @param text the digits.
 * @return the bytes.
 */
std::vector<uint8_t>
HexBytes(const std::string& text)
{
    std::vector<uint8_t> bytes;
    for (size_t k = 0; k + 1 < text.size(); k += 2)
    {
        bytes.push_back(static_cast<uint8_t>(std::stoi(text.substr(k, 2), nullptr, 16)));
    }
    return bytes;
}

/**
 * The bytes of the frames, from the vectors of RFC 9000 and RFC 9001 Appendix A, and the frames
 * written and read back.
 */
class FramesWireTest : public TestCase
{
  public:
    FramesWireTest()
        : TestCase("frames: bytes of every frame, and a round trip")
    {
    }

  private:
    void Expect(const char* what, const QuicSubheader& frame, const std::string& hex)
    {
        const std::vector<uint8_t> want = HexBytes(hex);
        const std::vector<uint8_t> got = FrameBytes(frame);
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), what << ": size");
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k], (uint32_t)want[k], what << ": byte " << k);
        }
        QuicSubheader back;
        NS_TEST_ASSERT_MSG_EQ(ReadFrame(want, back), want.size(), what << ": bytes read");
        NS_TEST_ASSERT_MSG_EQ(back.IsValid(), true, what << ": valid");
        NS_TEST_ASSERT_MSG_EQ(FrameBytes(back) == want,
                              true,
                              what << ": the frame read writes the same bytes");
    }

    void DoRun() override
    {
        Expect("PADDING", QuicSubheader::CreatePadding(), "00");
        Expect("PING", QuicSubheader::CreatePing(), "01");
        Expect("HANDSHAKE_DONE", QuicSubheader::CreateHandshakeDone(), "1e");
        // RFC 9001 A.2: the CRYPTO frame of the client Initial: offset 0, length 241
        Expect("CRYPTO", QuicSubheader::CreateCrypto(0, 241), "060040f1");
        Expect("NEW_TOKEN",
               QuicSubheader::CreateNewToken({'t', 'o', 'k', 'e', 'n'}),
               "070574"
               "6f6b656e");

        // ACK: largest 1000, delay 250, ranges 996-1000, 990-993, 980-985
        std::vector<uint64_t> gaps = {995, 989}, blocks = {993, 985};
        Expect("ACK",
               QuicSubheader::CreateAck(1000, 250, 980, gaps, blocks),
               "0243e840fa0204010303"
               "05");
        // ACK with ECN counts (RFC 9000 Section 19.3.2)
        QuicSubheader ecn = QuicSubheader::CreateAck(7, 0, 7, gaps = {}, blocks = {});
        ecn.SetEcnCounts(10, 2, 1);
        Expect("ACK_ECN",
               ecn,
               "0307000000"
               "0a0201");

        // error codes are variable-length integers of up to 62 bits
        Expect("RESET_STREAM", QuicSubheader::CreateRstStream(5, 11, 4096), "04050b5000");
        Expect("RESET_STREAM, a 62-bit error code",
               QuicSubheader::CreateRstStream(5, 0x3fffffffffffffffULL, 4096),
               "0405"
               "ffffffffffffffff"
               "5000");
        Expect("STOP_SENDING", QuicSubheader::CreateStopSending(9, 7), "050907");
        Expect("STOP_SENDING, an error code above 16 bits",
               QuicSubheader::CreateStopSending(9, 0x12345678ULL),
               "0509"
               "92345678");
        Expect("CONNECTION_CLOSE", QuicSubheader::CreateConnectionClose(0x0a, "x"), "1c0a000178");
        Expect("CONNECTION_CLOSE, application",
               QuicSubheader::CreateApplicationClose(0x0a, "x"),
               "1d0a0178");
        Expect("CONNECTION_CLOSE, a code above 16 bits",
               QuicSubheader::CreateConnectionClose(0x1000a, "x"),
               "1c"
               "8001000a"
               "00"
               "0178");

        // STREAM, with and without the OFF, LEN and FIN bits
        Expect("STREAM",
               QuicSubheader::CreateStreamSubHeader(4, 0, 5, false, true, false),
               "0a0405");
        Expect("STREAM, OFF LEN FIN",
               QuicSubheader::CreateStreamSubHeader(4, 100, 5, true, true, true),
               "0f044064"
               "05");
        Expect("STREAM, OFF and no LEN",
               QuicSubheader::CreateStreamSubHeader(4, 100, 0, true, false, false),
               "0c044064");
        Expect("STREAM, FIN and no data",
               QuicSubheader::CreateStreamSubHeader(8, 0, 0, false, true, true),
               "0b0800");

        Expect("MAX_DATA", QuicSubheader::CreateMaxData(1000), "1043e8");
        Expect("MAX_STREAM_DATA",
               QuicSubheader::CreateMaxStreamData(4, 65536),
               "11048001"
               "0000");
        Expect("DATA_BLOCKED", QuicSubheader::CreateBlocked(7), "1407");
        Expect("STREAM_DATA_BLOCKED", QuicSubheader::CreateStreamBlocked(4, 7), "150407");

        // NEW_CONNECTION_ID with ids of 1 and of 20 bytes, and the reset token
        const uint8_t one[1] = {0x55};
        Expect("NEW_CONNECTION_ID, 1 byte",
               QuicSubheader::CreateNewConnectionId(1,
                                                    0,
                                                    QuicConnectionId(one, 1),
                                                    0x0102030405060708ULL,
                                                    0x090a0b0c0d0e0f10ULL),
               "1801000155"
               "0102030405060708"
               "090a0b0c0d0e0f10");
        uint8_t twenty[20];
        for (uint8_t k = 0; k < 20; ++k)
        {
            twenty[k] = k + 1;
        }
        Expect("NEW_CONNECTION_ID, 20 bytes",
               QuicSubheader::CreateNewConnectionId(2, 1, QuicConnectionId(twenty, 20), 1, 2),
               "180201"
               "14"
               "0102030405060708090a0b0c0d0e0f1011121314"
               "0000000000000001"
               "0000000000000002");
        Expect("RETIRE_CONNECTION_ID", QuicSubheader::CreateRetireConnectionId(3), "1903");
        Expect("PATH_CHALLENGE",
               QuicSubheader::CreatePathChallenge(0x0102030405060708ULL),
               "1a0102030405060708");
        Expect("PATH_RESPONSE",
               QuicSubheader::CreatePathResponse(0x0102030405060708ULL),
               "1b0102030405060708");

        // the draft-ietf-quic-ack-frequency frames: the type 0xaf is a two-byte variable-length
        // integer
        Expect("ACK_FREQUENCY",
               QuicSubheader::CreateAckFrequency(7, 41, 25000, 1),
               "40af0729"
               "800061a8"
               "01");
        Expect("IMMEDIATE_ACK", QuicSubheader::CreateImmediateAck(), "1f");
    }
};

/**
 * The frames each packet type may carry (RFC 9000, Section 12.4, Table 3).
 */
class FramesAllowedTest : public TestCase
{
  public:
    FramesAllowedTest()
        : TestCase("frames: the packet types that may carry each frame (RFC 9000 s12.4)")
    {
    }

  private:
    void Expect(const char* what, const QuicSubheader& frame, const std::string& types)
    {
        // I Initial, Z 0-RTT, H Handshake, O 1-RTT
        const std::pair<char, QuicPacketType> all[] = {{'I', QuicPacketType::INITIAL},
                                                       {'Z', QuicPacketType::ZERO_RTT},
                                                       {'H', QuicPacketType::HANDSHAKE},
                                                       {'O', QuicPacketType::ONE_RTT}};
        for (const auto& type : all)
        {
            NS_TEST_ASSERT_MSG_EQ(frame.IsAllowedIn(type.second),
                                  types.find(type.first) != std::string::npos,
                                  what << " in a packet of type " << type.first);
        }
    }

    void DoRun() override
    {
        std::vector<uint64_t> none;
        Expect("PADDING", QuicSubheader::CreatePadding(), "IZHO");
        Expect("PING", QuicSubheader::CreatePing(), "IZHO");
        Expect("ACK", QuicSubheader::CreateAck(5, 0, 5, none, none), "IHO");
        Expect("CRYPTO", QuicSubheader::CreateCrypto(0, 10), "IHO");
        Expect("CONNECTION_CLOSE", QuicSubheader::CreateConnectionClose(0, "x"), "IHO");
        Expect("CONNECTION_CLOSE (application)",
               QuicSubheader::CreateApplicationClose(0, "x"),
               "ZO");
        Expect("NEW_TOKEN", QuicSubheader::CreateNewToken({1}), "O");
        Expect("PATH_RESPONSE", QuicSubheader::CreatePathResponse(1), "O");
        Expect("HANDSHAKE_DONE", QuicSubheader::CreateHandshakeDone(), "O");
        Expect("STREAM", QuicSubheader::CreateStreamSubHeader(0, 0, 1, false, true, false), "ZO");
        Expect("RESET_STREAM", QuicSubheader::CreateRstStream(0, 0, 0), "ZO");
        Expect("MAX_DATA", QuicSubheader::CreateMaxData(1), "ZO");
        Expect("NEW_CONNECTION_ID",
               QuicSubheader::CreateNewConnectionId(1, 0, QuicConnectionId::FromUint64(1), 0, 0),
               "ZO");
        Expect("PATH_CHALLENGE", QuicSubheader::CreatePathChallenge(1), "ZO");
        Expect("ACK_FREQUENCY", QuicSubheader::CreateAckFrequency(1, 2, 1000, 1), "ZO");
    }
};

/**
 * Frames that are not valid are recognized, whatever bytes they are cut from.
 */
class FramesInvalidTest : public TestCase
{
  public:
    FramesInvalidTest()
        : TestCase("frames: truncated, undefined and non-minimal frames are not valid")
    {
    }

  private:
    void ExpectInvalid(const char* what, const std::vector<uint8_t>& bytes, uint64_t error)
    {
        QuicSubheader frame;
        const uint32_t used = ReadFrame(bytes, frame);
        NS_TEST_ASSERT_MSG_EQ(frame.IsValid(), false, what << ": valid");
        NS_TEST_ASSERT_MSG_EQ(frame.GetParseError(), error, what << ": error code");
        NS_TEST_ASSERT_MSG_EQ(used,
                              bytes.size(),
                              what << ": a bad frame takes the rest of the packet");
    }

    void DoRun() override
    {
        // every frame cut short is not valid
        std::vector<std::vector<uint8_t>> frames = {
            FrameBytes(QuicSubheader::CreateRstStream(5, 11, 4096)),
            FrameBytes(QuicSubheader::CreateStopSending(9, 7)),
            FrameBytes(QuicSubheader::CreateCrypto(300, 241)),
            FrameBytes(QuicSubheader::CreateNewToken({1, 2, 3})),
            FrameBytes(QuicSubheader::CreateStreamSubHeader(4, 100, 5, true, true, true)),
            FrameBytes(QuicSubheader::CreateMaxData(100000)),
            FrameBytes(QuicSubheader::CreateMaxStreamData(4, 65536)),
            FrameBytes(QuicSubheader::CreateConnectionClose(0x0a, "reason")),
            FrameBytes(QuicSubheader::CreateApplicationClose(0x0a, "reason")),
            FrameBytes(
                QuicSubheader::CreateNewConnectionId(2, 1, QuicConnectionId::FromUint64(5), 1, 2)),
            FrameBytes(QuicSubheader::CreatePathChallenge(9)),
            FrameBytes(QuicSubheader::CreateAckFrequency(7, 41, 25000, 1)),
        };
        std::vector<uint64_t> gaps = {995, 989}, blocks = {993, 985};
        frames.push_back(FrameBytes(QuicSubheader::CreateAck(1000, 250, 980, gaps, blocks)));
        for (const auto& frame : frames)
        {
            for (size_t cut = 1; cut < frame.size(); ++cut)
            {
                // a frame cut in the middle of a payload that the frame announces is the L5 layer's
                // to detect, so the check stops at the fields
                std::vector<uint8_t> shorter(frame.begin(), frame.begin() + cut);
                QuicSubheader parsed;
                const uint32_t used = ReadFrame(shorter, parsed);
                NS_TEST_ASSERT_MSG_LT_OR_EQ(used,
                                            shorter.size(),
                                            "the read stays inside the bytes");
                if (parsed.IsValid())
                {
                    // only a frame whose fields end before the cut can be valid, such as a CRYPTO
                    // or STREAM frame whose data would follow
                    NS_TEST_ASSERT_MSG_EQ(parsed.IsCrypto() || parsed.IsStream() ||
                                              parsed.IsNewToken(),
                                          false,
                                          "a cut frame is read as a whole one");
                }
            }
        }
        ExpectInvalid("empty", {}, QuicSubheader::FRAME_ENCODING_ERROR);
        // RFC 9000 Section 12.4: an unknown type is a FRAME_ENCODING_ERROR
        ExpectInvalid("type 0x20", {0x20, 0, 0}, QuicSubheader::FRAME_ENCODING_ERROR);
        ExpectInvalid("type 0x2f", {0x2f}, QuicSubheader::FRAME_ENCODING_ERROR);
        ExpectInvalid("type 0x40ff", {0x40, 0xff}, QuicSubheader::FRAME_ENCODING_ERROR);
        ExpectInvalid("type 0x3e75, a Multipath frame without negotiation",
                      {0x7e, 0x75, 1, 0},
                      QuicSubheader::FRAME_ENCODING_ERROR);
        // a frame type has to use its shortest encoding
        ExpectInvalid("PING as two bytes", {0x40, 0x01}, QuicSubheader::PROTOCOL_VIOLATION);
        ExpectInvalid("ACK_FREQUENCY in a four-byte form",
                      {0x80, 0x00, 0x00, 0xaf, 1, 2, 3, 4},
                      QuicSubheader::PROTOCOL_VIOLATION);
        // ACK ranges that fall below packet number 0
        ExpectInvalid("ACK, first range above the largest",
                      {0x02, 0x05, 0x00, 0x00, 0x07},
                      QuicSubheader::FRAME_ENCODING_ERROR);
        ExpectInvalid("ACK, a gap below 0",
                      {0x02, 0x05, 0x00, 0x01, 0x00, 0x09, 0x00},
                      QuicSubheader::FRAME_ENCODING_ERROR);
        ExpectInvalid("ACK, more ranges than bytes",
                      {0x02, 0x05, 0x00, 0x3f, 0x00},
                      QuicSubheader::FRAME_ENCODING_ERROR);
        // RFC 9000 Section 19.7: a token is not empty
        ExpectInvalid("NEW_TOKEN with no token", {0x07, 0x00}, QuicSubheader::FRAME_ENCODING_ERROR);
        // RFC 9000 Section 19.15: a connection id has 1 to 20 bytes
        ExpectInvalid("NEW_CONNECTION_ID with an empty id",
                      HexBytes("18010000"
                               "00000000000000010000000000000002"),
                      QuicSubheader::FRAME_ENCODING_ERROR);
        ExpectInvalid("NEW_CONNECTION_ID with an id of 21 bytes",
                      HexBytes("180100150102030405060708090a0b0c0d0e0f101112131415"
                               "00000000000000010000000000000002"),
                      QuicSubheader::FRAME_ENCODING_ERROR);
        // a run of zeros is one PADDING frame
        QuicSubheader padding;
        NS_TEST_ASSERT_MSG_EQ(ReadFrame(std::vector<uint8_t>(100, 0), padding),
                              100u,
                              "a run of PADDING");
        NS_TEST_ASSERT_MSG_EQ(padding.IsValid(), true, "PADDING is valid");

        // frames made of random bytes are read without going past them, and the read always ends
        std::mt19937 rng(42);
        for (int round = 0; round < 20000; ++round)
        {
            std::vector<uint8_t> bytes(1 + rng() % 40);
            for (auto& b : bytes)
            {
                b = static_cast<uint8_t>(rng());
            }
            std::vector<uint8_t> rest = bytes;
            for (int guard = 0; guard < 100 && !rest.empty(); ++guard)
            {
                QuicSubheader frame;
                const uint32_t used = ReadFrame(rest, frame);
                NS_TEST_ASSERT_MSG_GT(used, 0u, "a frame takes at least a byte");
                NS_TEST_ASSERT_MSG_LT_OR_EQ(used, rest.size(), "a frame stays inside the packet");
                uint32_t skip =
                    used + static_cast<uint32_t>(frame.GetPayloadLength(rest.size() - used) >
                                                         rest.size() - used
                                                     ? rest.size() - used
                                                     : frame.GetPayloadLength(rest.size() - used));
                skip = std::min<uint32_t>(skip, rest.size());
                rest.erase(rest.begin(), rest.begin() + skip);
            }
        }
    }
};

/**
 * What a receiver does with the frames of a packet that are not valid: it closes the connection
 * with the error of the RFC. The frames go in place of the data of one packet of an open
 * connection.
 */
class FramesReceivedTest : public TestCase
{
  public:
    FramesReceivedTest(std::string what,
                       std::vector<uint8_t> frames,
                       bool survives,
                       uint64_t received)
        : TestCase("frames: " + what),
          m_frames(std::move(frames)),
          m_survives(survives),
          m_received(received)
    {
    }

  private:
    void DoRun() override
    {
        InjectionScenario scenario(m_frames);
        scenario.Run();
        NS_TEST_ASSERT_MSG_EQ(scenario.Injected(), true, "the frames were injected");
        if (m_survives)
        {
            NS_TEST_ASSERT_MSG_EQ(scenario.ServerState(), QuicSocket::OPEN, "server state");
            NS_TEST_ASSERT_MSG_EQ(scenario.ClientState(), QuicSocket::OPEN, "client state");
        }
        else
        {
            NS_TEST_ASSERT_MSG_NE(scenario.ServerState(),
                                  QuicSocket::OPEN,
                                  "the server closed the connection");
        }
        NS_TEST_ASSERT_MSG_EQ(scenario.ServerRx(),
                              m_received,
                              "bytes delivered to the application");
    }

    std::vector<uint8_t> m_frames;
    bool m_survives;
    uint64_t m_received;
};

class QuicFramesTestSuite : public TestSuite
{
  public:
    QuicFramesTestSuite()
        : TestSuite("quic-frames", Type::UNIT)
    {
        AddTestCase(new FramesWireTest, TestCase::Duration::QUICK);
        AddTestCase(new FramesAllowedTest, TestCase::Duration::QUICK);
        AddTestCase(new FramesInvalidTest, TestCase::Duration::QUICK);
        // a PING in place of the data: the connection stays open (control of the cases below)
        AddTestCase(new FramesReceivedTest("a PING in a packet changes nothing", {0x01}, true, 0),
                    TestCase::Duration::QUICK);
        // RFC 9000 Section 19.3.2: ACK_ECN is a valid frame
        AddTestCase(new FramesReceivedTest("a connection survives an ACK_ECN frame",
                                           {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                           true,
                                           0),
                    TestCase::Duration::QUICK);
        // RFC 9000 Section 19.8: a STREAM frame with LEN and a length of zero ends where its fields
        // end, and the PING behind it is read as a frame
        AddTestCase(new FramesReceivedTest(
                        "a STREAM frame of length zero does not swallow the frames behind it",
                        {0x0b, 0x00, 0x00, 0x01},
                        true,
                        0),
                    TestCase::Duration::QUICK);
        // RFC 9000 Section 12.4: an unknown type, a length beyond the packet and a type that is not
        // in its shortest form end the connection
        AddTestCase(new FramesReceivedTest("an undefined frame type closes the connection",
                                           {0x20},
                                           false,
                                           0),
                    TestCase::Duration::QUICK);
        AddTestCase(
            new FramesReceivedTest(
                "a frame that announces more data than the packet has closes the connection",
                {0x0a, 0x00, 0x7f, 0xff},
                false,
                0),
            TestCase::Duration::QUICK);
        AddTestCase(new FramesReceivedTest(
                        "a frame type that is longer than it has to be closes the connection",
                        {0x40, 0x01},
                        false,
                        0),
                    TestCase::Duration::QUICK);
    }
};

QuicFramesTestSuite g_quicFramesTestSuite;

} // namespace
