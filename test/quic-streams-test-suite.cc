/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - stream suite ("quic-streams").
 *
 * What a receiver does with the frames of a stream that disagree about its size or arrive in a
 * state that has no use for them (RFC 9000, Section 3 and Section 4.5): the final size never
 * changes and nothing goes beyond it, a copy of data that was read is ignored, and a RESET_STREAM
 * that comes after all the data is not an error. The frames go in place of the data of one packet
 * of an open connection.
 */

#include "../model/quic-subheader.h"
#include "quic-injection.h"

#include "ns3/test.h"

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
 * @return the bytes.
 */
std::vector<uint8_t>
Bytes(const QuicSubheader& frame)
{
    Buffer buffer;
    buffer.AddAtStart(frame.GetSerializedSize());
    frame.Serialize(buffer.Begin());
    std::vector<uint8_t> bytes(buffer.GetSize());
    buffer.CopyData(bytes.data(), bytes.size());
    return bytes;
}

/**
 * A STREAM frame with its data.
 *
 * @param stream the stream id.
 * @param offset the offset of the data.
 * @param length the number of bytes of data.
 * @param fin true when the frame ends the stream.
 * @return the frame and the data.
 */
std::vector<uint8_t>
StreamFrame(uint64_t stream, uint64_t offset, uint32_t length, bool fin)
{
    std::vector<uint8_t> bytes =
        Bytes(QuicSubheader::CreateStreamSubHeader(stream, offset, length, offset > 0, true, fin));
    bytes.insert(bytes.end(), length, 0xaa);
    return bytes;
}

/**
 * Frames one after the other.
 *
 * @param parts the frames.
 * @return their bytes.
 */
std::vector<uint8_t>
Concat(const std::vector<std::vector<uint8_t>>& parts)
{
    std::vector<uint8_t> all;
    for (const auto& part : parts)
    {
        all.insert(all.end(), part.begin(), part.end());
    }
    return all;
}

constexpr uint64_t kAnyBytes = UINT64_MAX; //!< the bytes delivered are not checked

/**
 * Frames put in a packet of a live connection, and what became of the connection.
 */
class StreamFramesTest : public TestCase
{
  public:
    StreamFramesTest(std::string what,
                     std::vector<uint8_t> frames,
                     bool survives,
                     uint64_t received)
        : TestCase("streams: " + what),
          m_frames(std::move(frames)),
          m_survives(survives),
          m_received(received)
    {
    }

  private:
    void DoRun() override
    {
        // the packet that is rewritten carries 100 bytes, so that there is room for the frames
        InjectionScenario scenario(m_frames, 100);
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
        if (m_received != kAnyBytes)
        {
            NS_TEST_ASSERT_MSG_EQ(scenario.ServerRx(), m_received, "bytes delivered");
        }
    }

    std::vector<uint8_t> m_frames;
    bool m_survives;
    uint64_t m_received;
};

class QuicStreamsTestSuite : public TestSuite
{
  public:
    QuicStreamsTestSuite()
        : TestSuite("quic-streams", Type::UNIT)
    {
        auto add = [this](std::string what,
                          std::vector<uint8_t> frames,
                          bool survives,
                          uint64_t received) {
            AddTestCase(
                new StreamFramesTest(std::move(what), std::move(frames), survives, received),
                TestCase::Duration::QUICK);
        };
        const auto fin5 = StreamFrame(0, 0, 5, true);

        // RFC 9000 Section 4.5: the final size is the offset plus the length of the frame with the
        // FIN bit, and it does not change
        add("a stream of 5 bytes is delivered", fin5, true, 5);
        add("a FIN that gives another final size closes the connection",
            Concat({fin5, StreamFrame(0, 0, 8, true)}),
            false,
            kAnyBytes);
        add("a FIN at the same final size from another frame is the same stream",
            Concat({StreamFrame(0, 0, 3, false),
                    StreamFrame(0, 3, 2, true),
                    StreamFrame(0, 3, 2, true)}),
            true,
            5);
        add("data beyond the final size closes the connection",
            Concat({fin5, StreamFrame(0, 5, 3, false)}),
            false,
            kAnyBytes);
        add("a FIN below the data that arrived closes the connection",
            Concat({StreamFrame(0, 0, 8, false), StreamFrame(0, 0, 5, true)}),
            false,
            kAnyBytes);

        // RFC 9000 Section 3.2: a copy of data that was read is ignored
        add("a copy of the last frame after the data was read is ignored",
            Concat({fin5, fin5}),
            true,
            5);
        add("a copy of an earlier frame after the data was read is ignored",
            Concat({StreamFrame(0, 0, 3, false),
                    StreamFrame(0, 3, 2, true),
                    StreamFrame(0, 0, 3, false)}),
            true,
            5);

        // RESET_STREAM after all the data arrived is not an error when the final size agrees
        add("a RESET_STREAM at the final size, after all the data, is ignored",
            Concat({fin5, Bytes(QuicSubheader::CreateRstStream(0, 7, 5))}),
            true,
            5);
        add("a RESET_STREAM with another final size closes the connection",
            Concat({fin5, Bytes(QuicSubheader::CreateRstStream(0, 7, 9))}),
            false,
            kAnyBytes);
        add("a RESET_STREAM below the data that arrived closes the connection",
            Concat({StreamFrame(0, 0, 8, false), Bytes(QuicSubheader::CreateRstStream(0, 7, 5))}),
            false,
            kAnyBytes);
        add("data beyond the final size of a RESET_STREAM closes the connection",
            Concat({Bytes(QuicSubheader::CreateRstStream(0, 7, 5)), StreamFrame(0, 5, 3, false)}),
            false,
            kAnyBytes);
        add("a RESET_STREAM that is repeated is ignored",
            Concat({Bytes(QuicSubheader::CreateRstStream(0, 7, 5)),
                    Bytes(QuicSubheader::CreateRstStream(0, 7, 5))}),
            true,
            0);

        // RFC 9000 Section 19.8: the end of the data stays below 2^62
        add("a STREAM frame that reaches beyond 2^62-1 closes the connection",
            StreamFrame(0, QUIC_VARINT_MAX, 1, false),
            false,
            kAnyBytes);
    }
};

QuicStreamsTestSuite g_quicStreamsTestSuite;

} // namespace
