/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - wire layer suite ("quic-wire").
 *
 * The building blocks of the wire format with the vectors of the RFCs: variable-length integers
 * (RFC 9000, Section 16 and Appendix A.1).
 */

#include "../model/quic-wire.h"

#include "ns3/buffer.h"
#include "ns3/test.h"

#include <vector>

using namespace ns3;

namespace
{

/**
 * Encode a value.
 *
 * @param value the value.
 * @return the bytes of the shortest encoding.
 */
std::vector<uint8_t>
Encode(uint64_t value)
{
    Buffer buffer;
    buffer.AddAtStart(8);
    Buffer::Iterator i = buffer.Begin();
    QuicWriteVarInt(i, value);
    const uint32_t size = i.GetDistanceFrom(buffer.Begin());
    std::vector<uint8_t> bytes(size);
    buffer.CopyData(bytes.data(), size);
    return bytes;
}

/**
 * Decode the bytes at the start of a buffer.
 *
 * @param bytes the bytes.
 * @param used set to the number of bytes read.
 * @return the value.
 */
uint64_t
Decode(const std::vector<uint8_t>& bytes, uint32_t& used)
{
    Buffer buffer;
    buffer.AddAtStart(bytes.size());
    buffer.Begin().Write(bytes.data(), bytes.size());
    Buffer::Iterator i = buffer.Begin();
    const uint64_t value = QuicReadVarInt(i);
    used = i.GetDistanceFrom(buffer.Begin());
    return value;
}

/**
 * The examples of RFC 9000, Appendix A.1, and the boundaries between the four lengths.
 */
class QuicWireVarIntTest : public TestCase
{
  public:
    QuicWireVarIntTest()
        : TestCase("varint: RFC 9000 appendix A.1 and the length boundaries")
    {
    }

  private:
    void Expect(uint64_t value, std::vector<uint8_t> want)
    {
        std::vector<uint8_t> got = Encode(value);
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), "size of " << value);
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k],
                                  (uint32_t)want[k],
                                  "byte " << k << " of " << value);
        }
        uint32_t used = 0;
        NS_TEST_ASSERT_MSG_EQ(Decode(want, used), value, "decoding " << value);
        NS_TEST_ASSERT_MSG_EQ(used, want.size(), "bytes read for " << value);
    }

    void DoRun() override
    {
        Expect(37, {0x25});
        Expect(15293, {0x7b, 0xbd});
        Expect(494878333, {0x9d, 0x7f, 0x3e, 0x7d});
        Expect(151288809941952652ULL, {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c});

        Expect(0, {0x00});
        Expect(63, {0x3f});
        Expect(64, {0x40, 0x40});
        Expect(16383, {0x7f, 0xff});
        Expect(16384, {0x80, 0x00, 0x40, 0x00});
        Expect((1ULL << 30) - 1, {0xbf, 0xff, 0xff, 0xff});
        Expect(1ULL << 30, {0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00});
        Expect(QUIC_VARINT_MAX, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});

        // a longer encoding than needed is valid when reading (RFC 9000, Appendix A.1)
        uint32_t used = 0;
        NS_TEST_ASSERT_MSG_EQ(Decode({0x40, 0x25}, used), 37u, "two-byte form of 37");
        NS_TEST_ASSERT_MSG_EQ(used, 2u, "bytes read for the two-byte form of 37");
        NS_TEST_ASSERT_MSG_EQ(Decode({0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0xff}, used),
                              37u,
                              "eight-byte form of 37");
        NS_TEST_ASSERT_MSG_EQ(used, 8u, "a read stops at the end of the integer");

        NS_TEST_ASSERT_MSG_EQ(QuicVarIntLength(63), 1u, "length of 63");
        NS_TEST_ASSERT_MSG_EQ(QuicVarIntLength(64), 2u, "length of 64");
        NS_TEST_ASSERT_MSG_EQ(QuicVarIntLength(16384), 4u, "length of 16384");
        NS_TEST_ASSERT_MSG_EQ(QuicVarIntLength(1ULL << 30), 8u, "length of 2^30");
        NS_TEST_ASSERT_MSG_EQ(QuicVarIntLength(QUIC_VARINT_MAX), 8u, "length of the largest value");
        NS_TEST_ASSERT_MSG_EQ(QuicVarIntLength(QUIC_VARINT_MAX + 1), 0u, "no length above 2^62-1");
    }
};

class QuicWireTestSuite : public TestSuite
{
  public:
    QuicWireTestSuite()
        : TestSuite("quic-wire", Type::UNIT)
    {
        AddTestCase(new QuicWireVarIntTest, TestCase::Duration::QUICK);
    }
};

QuicWireTestSuite g_quicWireTestSuite;

} // namespace
