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
 * (RFC 9000, Section 16 and Appendix A.1), connection ids (RFC 9000, Section 5.1), packet numbers
 * (RFC 9000, Appendix A.2 and A.3) and the packet headers (RFC 8999, RFC 9000, Section 17), with
 * the unprotected packets of RFC 9001 Appendix A and the examples of RFC 9369.
 */

#include "../model/quic-connection-id.h"
#include "../model/quic-header.h"
#include "../model/quic-transport-parameters.h"
#include "../model/quic-wire.h"

#include "ns3/buffer.h"
#include "ns3/test.h"

#include <sstream>
#include <string>
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

/**
 * Connection ids of 0 to 20 bytes: bytes, length, order, writing and reading.
 */
class QuicWireConnectionIdTest : public TestCase
{
  public:
    QuicWireConnectionIdTest()
        : TestCase("connection id: length, order, serialization and printing")
    {
    }

  private:
    void DoRun() override
    {
        QuicConnectionId empty;
        NS_TEST_ASSERT_MSG_EQ(empty.IsEmpty(), true, "a default id is empty");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)empty.GetLength(), 0u, "length of the empty id");

        QuicConnectionId eight = QuicConnectionId::FromUint64(0x0102030405060708ULL);
        NS_TEST_ASSERT_MSG_EQ((uint32_t)eight.GetLength(), 8u, "length of an id from a number");
        NS_TEST_ASSERT_MSG_EQ(eight.ToUint64(), 0x0102030405060708ULL, "number of the id");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)eight.GetBytes()[0], 1u, "most significant byte first");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)eight.GetBytes()[7], 8u, "least significant byte last");

        // ids of different lengths differ even when one is the prefix of the other
        const uint8_t bytes[20] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        QuicConnectionId prefix(bytes, 8);
        QuicConnectionId longest(bytes, 20);
        NS_TEST_ASSERT_MSG_EQ((uint32_t)longest.GetLength(), 20u, "longest id");
        NS_TEST_ASSERT_MSG_EQ(prefix == eight, true, "same bytes, same id");
        NS_TEST_ASSERT_MSG_EQ(prefix == longest, false, "a prefix is another id");
        NS_TEST_ASSERT_MSG_EQ(prefix < longest, true, "the shorter id sorts first");
        NS_TEST_ASSERT_MSG_EQ(longest < prefix, false, "the longer id sorts last");
        NS_TEST_ASSERT_MSG_EQ(QuicConnectionId::FromUint64(255) < QuicConnectionId::FromUint64(256),
                              true,
                              "ids of one length sort as numbers");
        NS_TEST_ASSERT_MSG_EQ(empty < prefix, true, "the empty id sorts first");

        // write and read back
        Buffer buffer;
        buffer.AddAtStart(20);
        Buffer::Iterator w = buffer.Begin();
        longest.Serialize(w);
        NS_TEST_ASSERT_MSG_EQ(w.GetDistanceFrom(buffer.Begin()), 20u, "bytes written");
        Buffer::Iterator r = buffer.Begin();
        QuicConnectionId back = QuicConnectionId::Deserialize(r, 20);
        NS_TEST_ASSERT_MSG_EQ(back == longest, true, "read back the id written");
        NS_TEST_ASSERT_MSG_EQ(r.GetDistanceFrom(buffer.Begin()), 20u, "bytes read");

        std::ostringstream text;
        text << QuicConnectionId::FromUint64(0x0a0b0c0d01020304ULL);
        NS_TEST_ASSERT_MSG_EQ(text.str(), "0a0b0c0d01020304", "hexadecimal form");
    }
};

/**
 * Bytes of a header.
 *
 * @param header the header.
 * @return the bytes it serializes to.
 */
std::vector<uint8_t>
HeaderBytes(const QuicHeader& header)
{
    Buffer buffer;
    buffer.AddAtStart(header.GetSerializedSize());
    header.Serialize(buffer.Begin());
    std::vector<uint8_t> bytes(buffer.GetSize());
    buffer.CopyData(bytes.data(), bytes.size());
    return bytes;
}

/**
 * Read a header from bytes, followed by other bytes.
 *
 * @param bytes the header.
 * @param extra number of bytes that follow the header.
 * @param header set to the header read.
 * @param used set to the number of bytes the header used.
 * @param shortCidLength length of the destination id of a short header.
 */
void
ReadHeader(const std::vector<uint8_t>& bytes,
           uint32_t extra,
           QuicHeader& header,
           uint32_t& used,
           uint8_t shortCidLength = 8)
{
    Buffer buffer;
    buffer.AddAtStart(bytes.size() + extra);
    buffer.Begin().Write(bytes.data(), bytes.size());
    header.SetShortHeaderConnectionIdLength(shortCidLength);
    used = header.Deserialize(buffer.Begin());
}

/**
 * Parse a string of hexadecimal digits.
 *
 * @param text the digits.
 * @return the bytes.
 */
std::vector<uint8_t>
Hex(const std::string& text)
{
    std::vector<uint8_t> bytes;
    for (size_t k = 0; k + 1 < text.size(); k += 2)
    {
        bytes.push_back(static_cast<uint8_t>(std::stoi(text.substr(k, 2), nullptr, 16)));
    }
    return bytes;
}

/**
 * The headers of RFC 9001 Appendix A, as the unprotected packets of the RFC show them, and the
 * same Retry and Initial headers in version 2 (RFC 9369, Section 3.2).
 */
class QuicWireHeaderVectorsTest : public TestCase
{
  public:
    QuicWireHeaderVectorsTest()
        : TestCase("header: RFC 9001 appendix A.2, A.3 and A.4, and QUIC version 2")
    {
    }

  private:
    void Expect(const char* what, const QuicHeader& header, const std::vector<uint8_t>& want)
    {
        std::vector<uint8_t> got = HeaderBytes(header);
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), what << ": size");
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k], (uint32_t)want[k], what << ": byte " << k);
        }
        // and the bytes read back as the same header
        QuicHeader back;
        uint32_t used = 0;
        ReadHeader(want, header.GetPayloadSize() + (header.HasPacketNumber() ? 0 : 16), back, used);
        NS_TEST_ASSERT_MSG_EQ(back.IsValid(), true, what << ": the header read is valid");
        NS_TEST_ASSERT_MSG_EQ(used, want.size(), what << ": bytes used");
        NS_TEST_ASSERT_MSG_EQ(back == header, true, what << ": read back");
    }

    void DoRun() override
    {
        // A.2: the client Initial. The Length 0x449e = 1182 is the 4 bytes of the packet number,
        // 1162 bytes of frames and the 16-byte tag.
        QuicHeader initial =
            QuicHeader::CreateInitial(QuicConnectionId(Hex("8394c8f03e515708").data(), 8),
                                      QuicConnectionId(),
                                      1,
                                      QuicPacketNumber(2));
        initial.SetPacketNumberLength(4);
        initial.SetPayloadSize(1162 + 16);
        Expect("A.2 client Initial", initial, Hex("c300000001088394c8f03e5157080000449e00000002"));

        // A.3: the server Initial, 2-byte packet number, Length 0x4075 = 117
        QuicHeader server =
            QuicHeader::CreateInitial(QuicConnectionId(),
                                      QuicConnectionId(Hex("f067a5502a4262b5").data(), 8),
                                      1,
                                      QuicPacketNumber(1));
        server.SetPacketNumberLength(2);
        server.SetPayloadSize(115);
        Expect("A.3 server Initial", server, Hex("c1000000010008f067a5502a4262b50040750001"));

        // A.4: Retry, token "token". The four low bits of the first byte are unused (the RFC writes
        // them as 1).
        QuicHeader retry =
            QuicHeader::CreateRetry(QuicConnectionId(),
                                    QuicConnectionId(Hex("f067a5502a4262b5").data(), 8),
                                    1,
                                    {'t', 'o', 'k', 'e', 'n'});
        std::vector<uint8_t> got = HeaderBytes(retry);
        NS_TEST_ASSERT_MSG_EQ((uint32_t)(got[0] & 0xf0),
                              0xf0u,
                              "Retry: long form, fixed bit, type 3");
        std::vector<uint8_t> want = Hex("ff000000010008f067a5502a4262b5746f6b656e");
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), "Retry: size");
        for (size_t k = 1; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k], (uint32_t)want[k], "Retry: byte " << k);
        }
        QuicHeader back;
        uint32_t used = 0;
        ReadHeader(want, 16, back, used);
        NS_TEST_ASSERT_MSG_EQ(back.IsRetry(), true, "Retry: type");
        NS_TEST_ASSERT_MSG_EQ(back.GetToken().size(), 5u, "Retry: token length");
        NS_TEST_ASSERT_MSG_EQ(back.GetSourceConnectionId().ToUint64(),
                              0xf067a5502a4262b5ULL,
                              "Retry: source id");

        // version 2 (RFC 9369, Section 3.2): Initial 0b01, 0-RTT 0b10, Handshake 0b11, Retry 0b00
        const QuicConnectionId cid = QuicConnectionId::FromUint64(0x0102030405060708ULL);
        auto first = [&](const QuicHeader& header) { return HeaderBytes(header)[0] & 0xf0; };
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(
                QuicHeader::CreateInitial(cid, cid, QUIC_VERSION_2, QuicPacketNumber(1))),
            0xd0u,
            "v2 Initial");
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(QuicHeader::Create0RTT(cid, cid, QUIC_VERSION_2, QuicPacketNumber(1))),
            0xe0u,
            "v2 0-RTT");
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(
                QuicHeader::CreateHandshake(cid, cid, QUIC_VERSION_2, QuicPacketNumber(1))),
            0xf0u,
            "v2 Handshake");
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(QuicHeader::CreateRetry(cid, cid, QUIC_VERSION_2, {1})),
            0xc0u,
            "v2 Retry");
        // and version 1: Initial 0b00, 0-RTT 0b01, Handshake 0b10, Retry 0b11
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(QuicHeader::CreateInitial(cid, cid, 1, QuicPacketNumber(1))),
            0xc0u,
            "v1 Initial");
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(QuicHeader::Create0RTT(cid, cid, 1, QuicPacketNumber(1))),
            0xd0u,
            "v1 0-RTT");
        NS_TEST_ASSERT_MSG_EQ(
            (uint32_t)first(QuicHeader::CreateHandshake(cid, cid, 1, QuicPacketNumber(1))),
            0xe0u,
            "v1 Handshake");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)first(QuicHeader::CreateRetry(cid, cid, 1, {1})),
                              0xf0u,
                              "v1 Retry");
        QuicHeader v2;
        uint32_t used2 = 0;
        ReadHeader(Hex("d36b3343cf0801020304050607080000400100"), 8, v2, used2);
        NS_TEST_ASSERT_MSG_EQ(v2.IsInitial(), true, "0xd3 with version 2 is an Initial");
    }
};

/**
 * Short headers, Version Negotiation, and the headers that are not valid.
 */
class QuicWireHeaderFormsTest : public TestCase
{
  public:
    QuicWireHeaderFormsTest()
        : TestCase("header: short header, Version Negotiation, packet numbers and invalid headers")
    {
    }

  private:
    void Expect(const char* what, const QuicHeader& header, const std::vector<uint8_t>& want)
    {
        std::vector<uint8_t> got = HeaderBytes(header);
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), what << ": size");
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k], (uint32_t)want[k], what << ": byte " << k);
        }
    }

    void DoRun() override
    {
        const QuicConnectionId cid = QuicConnectionId::FromUint64(0x0102030405060708ULL);

        // RFC 9000, Section 17.3.1: 0 | fixed bit | spin | 00 | key phase | packet number length
        Expect("short, spin and key phase, 1-byte number",
               QuicHeader::CreateShort(cid, QuicPacketNumber(5), true, true),
               {0x64, 1, 2, 3, 4, 5, 6, 7, 8, 0x05});
        // the number of bytes follows the packets the peer has not acknowledged
        Expect("short, 2-byte number",
               QuicHeader::CreateShort(cid, QuicPacketNumber(300), false, false),
               {0x41, 1, 2, 3, 4, 5, 6, 7, 8, 0x01, 0x2c});
        Expect("short, 1-byte number, the peer is up to date",
               QuicHeader::CreateShort(cid, QuicPacketNumber(300), false, false, 290),
               {0x40, 1, 2, 3, 4, 5, 6, 7, 8, 0x2c});
        Expect("short, 3-byte number",
               QuicHeader::CreateShort(cid, QuicPacketNumber(70000), false, false),
               {0x42, 1, 2, 3, 4, 5, 6, 7, 8, 0x01, 0x11, 0x70});
        // an id of another length
        const uint8_t twenty[20] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        QuicHeader longId =
            QuicHeader::CreateShort(QuicConnectionId(twenty, 20), QuicPacketNumber(1));
        QuicHeader back;
        uint32_t used = 0;
        ReadHeader(HeaderBytes(longId), 5, back, used, 20);
        NS_TEST_ASSERT_MSG_EQ(back.GetDestinationConnectionId() == QuicConnectionId(twenty, 20),
                              true,
                              "a 20-byte destination id reads back");
        NS_TEST_ASSERT_MSG_EQ(back.GetPacketNumber().GetValue(), 1u, "packet number");
        NS_TEST_ASSERT_MSG_EQ(back.GetPayloadSize(), 5u, "a short header packet runs to the end");

        // Version Negotiation (RFC 8999, Section 6): the connection ids of the client, swapped, and
        // the versions
        const QuicConnectionId clientDcid = QuicConnectionId::FromUint64(0xaabbccddeeff0011ULL);
        std::vector<uint32_t> versions = {1, 0x1a2a3a4a};
        QuicHeader vn = QuicHeader::CreateVersionNegotiation(cid, clientDcid, versions);
        Expect("Version Negotiation",
               vn,
               Hex("c000000000080102030405060708"
                   "08aabbccddeeff0011"
                   "00000001"
                   "1a2a3a4a"));
        ReadHeader(HeaderBytes(vn), 0, back, used);
        NS_TEST_ASSERT_MSG_EQ(back.IsVersionNegotiation(),
                              true,
                              "version 0 is Version Negotiation");
        NS_TEST_ASSERT_MSG_EQ(back.GetSupportedVersions().size(), 2u, "versions listed");
        NS_TEST_ASSERT_MSG_EQ(back.GetSupportedVersions()[1], 0x1a2a3a4aU, "second version");
        NS_TEST_ASSERT_MSG_EQ(back.GetSourceConnectionId() == clientDcid, true, "source id");

        // packet number length and recovery (RFC 9000, Appendix A.2 and A.3)
        NS_TEST_ASSERT_MSG_EQ((uint32_t)QuicPacketNumberLength(0, -1), 1u, "first packet");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)QuicPacketNumberLength(255, 250), 1u, "6 in flight");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)QuicPacketNumberLength(300, 100), 2u, "200 in flight");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)QuicPacketNumberLength(0xac5c02, 0xabe8b3),
                              2u,
                              "RFC 9000 A.2 example");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)QuicPacketNumberLength(0xace8fe, 0xabe8b3),
                              3u,
                              "RFC 9000 A.2 example, 3 bytes");
        NS_TEST_ASSERT_MSG_EQ(QuicDecodePacketNumber(0xa82f30ea, 0x9b32, 2),
                              0xa82f9b32ULL,
                              "RFC 9000 A.3 example");
        NS_TEST_ASSERT_MSG_EQ(QuicDecodePacketNumber(-1, 0, 1), 0ULL, "first packet");
        NS_TEST_ASSERT_MSG_EQ(QuicDecodePacketNumber(255, 0x00, 1), 256ULL, "wraps up");
        NS_TEST_ASSERT_MSG_EQ(QuicDecodePacketNumber(256, 0xff, 1),
                              255ULL,
                              "reordered, wraps down");
        // a header read gives the truncated number, and the full one once it is recovered
        QuicHeader truncated;
        ReadHeader(Hex("419b32"), 0, truncated, used, 0);
        NS_TEST_ASSERT_MSG_EQ(truncated.GetPacketNumber().GetValue(),
                              0x9b32ULL,
                              "truncated number");
        truncated.ReconstructPacketNumber(0xa82f30ea);
        NS_TEST_ASSERT_MSG_EQ(truncated.GetPacketNumber().GetValue(),
                              0xa82f9b32ULL,
                              "recovered number");

        // invalid headers
        auto valid = [&](const std::vector<uint8_t>& bytes, uint32_t extra) {
            QuicHeader h;
            uint32_t n = 0;
            ReadHeader(bytes, extra, h, n);
            return h.IsValid();
        };
        std::vector<uint8_t> good = Hex("40010203040506070805");
        NS_TEST_ASSERT_MSG_EQ(valid(good, 3), true, "a short header");
        NS_TEST_ASSERT_MSG_EQ(valid({0x00, 1, 2, 3, 4, 5, 6, 7, 8, 5}, 3), false, "Fixed Bit is 0");
        NS_TEST_ASSERT_MSG_EQ(valid({0x48, 1, 2, 3, 4, 5, 6, 7, 8, 5}, 3),
                              false,
                              "reserved bit is 1");
        NS_TEST_ASSERT_MSG_EQ(valid({0x40, 1, 2, 3}, 0), false, "short header too short");
        std::vector<uint8_t> initial = Hex("c3000000010801020304050607080000449e00000002");
        NS_TEST_ASSERT_MSG_EQ(valid(initial, 1178), true, "an Initial whose Length fits");
        NS_TEST_ASSERT_MSG_EQ(valid(initial, 1000), false, "Length beyond the packet");
        NS_TEST_ASSERT_MSG_EQ(valid(Hex("c3000000011501"), 100),
                              false,
                              "connection id of 21 bytes");
        NS_TEST_ASSERT_MSG_EQ(valid(Hex("83000000010801020304050607080000449e00000002"), 1178),
                              false,
                              "Fixed Bit is 0 in a long header");
        NS_TEST_ASSERT_MSG_EQ(valid(Hex("c7000000010801020304050607080000449e00000002"), 1178),
                              false,
                              "reserved bit set in a long header");
        NS_TEST_ASSERT_MSG_EQ(valid(Hex("c30000"), 0), false, "long header too short");
    }
};

/**
 * Read transport parameters from bytes.
 *
 * @param bytes the bytes.
 * @param parameters set to the parameters read.
 * @return the number of bytes used.
 */
uint32_t
ReadParameters(const std::vector<uint8_t>& bytes, QuicTransportParameters& parameters)
{
    Buffer buffer;
    buffer.AddAtStart(bytes.size());
    if (!bytes.empty())
    {
        buffer.Begin().Write(bytes.data(), bytes.size());
    }
    return parameters.Deserialize(buffer.Begin());
}

/**
 * The transport parameters as RFC 9000, Section 18 lists them: the ones of the client Initial of
 * RFC 9001 Appendix A.2, the defaults that are left out, and every way that they can be invalid.
 */
class QuicWireTransportParametersTest : public TestCase
{
  public:
    QuicWireTransportParametersTest()
        : TestCase("transport parameters: RFC 9001 appendix A.2, defaults, unknown and invalid")
    {
    }

  private:
    /** The list of parameters behind the length that this module writes in front of it. */
    static std::vector<uint8_t> List(const std::string& entries)
    {
        std::vector<uint8_t> bytes = Hex(entries);
        std::vector<uint8_t> list;
        list.push_back(static_cast<uint8_t>(bytes.size())); // short lists: one-byte length
        list.insert(list.end(), bytes.begin(), bytes.end());
        return list;
    }

    void ExpectInvalid(const char* what, const std::string& entries)
    {
        QuicTransportParameters tp;
        ReadParameters(List(entries), tp);
        NS_TEST_ASSERT_MSG_EQ(tp.IsValid(), false, what);
    }

    void DoRun() override
    {
        // the parameters of the client in RFC 9001 appendix A.2, read from the ClientHello
        const std::string rfc = "0408ffffffffffffffff"
                                "05048000ffff"
                                "07048000ffff"
                                "080110"
                                "010480007530"
                                "090110"
                                "0f088394c8f03e515708"
                                "06048000ffff";
        QuicTransportParameters a2;
        const std::vector<uint8_t> a2Bytes = List(rfc);
        NS_TEST_ASSERT_MSG_EQ(ReadParameters(a2Bytes, a2), a2Bytes.size(), "A.2: bytes used");
        NS_TEST_ASSERT_MSG_EQ(a2.IsValid(), true, "A.2: valid");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialMaxData(), QUIC_VARINT_MAX, "A.2: initial_max_data");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialMaxStreamData(),
                              65535u,
                              "A.2: initial_max_stream_data_bidi_local");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialMaxStreamDataBidiRemote(),
                              65535u,
                              "A.2: initial_max_stream_data_bidi_remote");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialMaxStreamDataUni(),
                              65535u,
                              "A.2: initial_max_stream_data_uni");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialMaxStreamIdBidi(), 16u, "A.2: initial_max_streams_bidi");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialMaxStreamIdUni(), 16u, "A.2: initial_max_streams_uni");
        NS_TEST_ASSERT_MSG_EQ(a2.GetIdleTimeout(), 30000u, "A.2: max_idle_timeout");
        NS_TEST_ASSERT_MSG_EQ(a2.GetInitialSourceConnectionId().ToUint64(),
                              0x8394c8f03e515708ULL,
                              "A.2: initial_source_connection_id");
        // a parameter that is not there has the default of RFC 9000
        NS_TEST_ASSERT_MSG_EQ((uint32_t)a2.GetAckDelayExponent(), 3u, "A.2: ack_delay_exponent");
        NS_TEST_ASSERT_MSG_EQ(a2.GetMaxAckDelay(), 25u, "A.2: max_ack_delay");
        NS_TEST_ASSERT_MSG_EQ(a2.GetActiveConnectionIdLimit(),
                              2u,
                              "A.2: active_connection_id_limit");
        NS_TEST_ASSERT_MSG_EQ(a2.GetMaxUdpPayloadSize(), 65527u, "A.2: max_udp_payload_size");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)a2.GetDisableActiveMigration(),
                              0u,
                              "A.2: disable_active_migration");

        // an empty list: every default
        QuicTransportParameters empty;
        empty.SetIdleTimeout(99);
        ReadParameters(Hex("00"), empty);
        NS_TEST_ASSERT_MSG_EQ(empty.IsValid(), true, "an empty list is valid");
        NS_TEST_ASSERT_MSG_EQ(empty.GetIdleTimeout(), 0u, "no idle timeout when it is not given");

        // what this module writes: the parameters that differ from the default, by identifier
        QuicTransportParameters tp;
        tp.SetIdleTimeout(30000);
        tp.SetInitialMaxData(1000000);
        tp.SetInitialMaxStreamIdBidi(16);
        tp.SetInitialSourceConnectionId(QuicConnectionId(Hex("8394c8f03e515708").data(), 8));
        const std::vector<uint8_t> want = Hex("19"
                                              "010480007530"
                                              "0404800f4240"
                                              "080110"
                                              "0f088394c8f03e515708");
        std::vector<uint8_t> got(tp.GetSerializedSize());
        {
            Buffer buffer;
            buffer.AddAtStart(tp.GetSerializedSize());
            tp.Serialize(buffer.Begin());
            buffer.CopyData(got.data(), got.size());
        }
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), "size of the parameters written");
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k],
                                  (uint32_t)want[k],
                                  "parameters written, byte " << k);
        }
        QuicTransportParameters back;
        ReadParameters(got, back);
        NS_TEST_ASSERT_MSG_EQ(back == tp, true, "the parameters read back are the ones written");

        // all of them, with ids that need two and eight bytes
        QuicTransportParameters full;
        full.SetIdleTimeout(1);
        full.SetInitialMaxData(2);
        full.SetInitialMaxStreamData(3);
        full.SetInitialMaxStreamDataBidiRemote(4);
        full.SetInitialMaxStreamDataUni(5);
        full.SetInitialMaxStreamIdBidi(6);
        full.SetInitialMaxStreamIdUni(7);
        full.SetMaxUdpPayloadSize(1472);
        full.SetAckDelayExponent(10);
        full.SetMaxAckDelay(40);
        full.SetMinAckDelay(1000);
        full.SetActiveConnectionIdLimit(4);
        full.SetDisableActiveMigration(1);
        full.SetStatelessResetToken(0x0102030405060708ULL, 0x090a0b0c0d0e0f10ULL);
        full.SetOriginalDestinationConnectionId(QuicConnectionId::FromUint64(1));
        full.SetInitialSourceConnectionId(QuicConnectionId::FromUint64(2));
        full.SetRetrySourceConnectionId(QuicConnectionId::FromUint64(3));
        full.SetRawParameter(0x1b, {1, 2, 3}); // reserved: 31 * 0 + 27
        Buffer buffer;
        buffer.AddAtStart(full.GetSerializedSize() + 100);
        full.Serialize(buffer.Begin());
        QuicTransportParameters fullBack;
        // padding follows the list, as in the handshake data
        const uint32_t used = fullBack.Deserialize(buffer.Begin());
        NS_TEST_ASSERT_MSG_EQ(used,
                              full.GetSerializedSize(),
                              "the list is read without the padding behind it");
        NS_TEST_ASSERT_MSG_EQ(fullBack.IsValid(), true, "full: valid");
        NS_TEST_ASSERT_MSG_EQ(fullBack == full, true, "full: read back");

        // a parameter that is not known is ignored and kept
        QuicTransportParameters unknown;
        ReadParameters(List("c0000000"), unknown);
        NS_TEST_ASSERT_MSG_EQ(unknown.IsValid(), false, "an identifier cut short is not valid");
        ReadParameters(List("1b03010203"
                            "6ab300"),
                       unknown);
        NS_TEST_ASSERT_MSG_EQ(unknown.IsValid(),
                              true,
                              "reserved and unknown parameters are ignored");
        NS_TEST_ASSERT_MSG_EQ(unknown.GetRawParameters().size(), 2u, "and kept");

        // RFC 9000 Section 7.4 and 18.2: these are errors
        ExpectInvalid("a repeated parameter",
                      "010100"
                      "010101");
        ExpectInvalid("ack_delay_exponent above 20", "0a0115");
        ExpectInvalid("max_ack_delay of 2^14", "0b0480004000");
        ExpectInvalid("max_udp_payload_size below 1200",
                      "03024"
                      "4af");
        ExpectInvalid("active_connection_id_limit below 2", "0e0101");
        ExpectInvalid("initial_max_streams_bidi above 2^60", "08081000000000000001");
        ExpectInvalid("stateless_reset_token of 15 bytes",
                      "020f"
                      "000102030405060708090a0b0c0d0e");
        ExpectInvalid("disable_active_migration with a value", "0c0100");
        ExpectInvalid("a connection id of 21 bytes",
                      "0f15"
                      "000102030405060708090a0b0c0d0e0f1011121314");
        ExpectInvalid("a number whose length is not the integer's",
                      "0104"
                      "4075"
                      "0000");
        ExpectInvalid("an entry that ends after the list", "01048000");
        ExpectInvalid("an identifier with no length", "01");
        // the list itself longer than the data
        QuicTransportParameters longer;
        ReadParameters(Hex("05"
                           "0100"),
                       longer);
        NS_TEST_ASSERT_MSG_EQ(longer.IsValid(), false, "a list longer than the bytes");

        // cut at every byte, and random bytes: never read past the data
        for (size_t cut = 0; cut <= got.size(); ++cut)
        {
            std::vector<uint8_t> shorter(got.begin(), got.begin() + cut);
            QuicTransportParameters partial;
            const uint32_t n = ReadParameters(shorter, partial);
            NS_TEST_ASSERT_MSG_LT_OR_EQ(n,
                                        std::max<size_t>(shorter.size(), 1),
                                        "the read stays inside the data");
        }
        for (uint32_t seed = 1; seed <= 3000; ++seed)
        {
            std::vector<uint8_t> noise(1 + seed % 50);
            uint32_t x = seed * 2654435761u;
            for (auto& b : noise)
            {
                x = x * 1664525u + 1013904223u;
                b = static_cast<uint8_t>(x >> 24);
            }
            QuicTransportParameters parsed;
            const uint32_t n = ReadParameters(noise, parsed);
            NS_TEST_ASSERT_MSG_LT_OR_EQ(n,
                                        noise.size(),
                                        "random bytes: the read stays inside the data");
        }
    }
};

class QuicWireTestSuite : public TestSuite
{
  public:
    QuicWireTestSuite()
        : TestSuite("quic-wire", Type::UNIT)
    {
        AddTestCase(new QuicWireVarIntTest, TestCase::Duration::QUICK);
        AddTestCase(new QuicWireConnectionIdTest, TestCase::Duration::QUICK);
        AddTestCase(new QuicWireHeaderVectorsTest, TestCase::Duration::QUICK);
        AddTestCase(new QuicWireHeaderFormsTest, TestCase::Duration::QUICK);
        AddTestCase(new QuicWireTransportParametersTest, TestCase::Duration::QUICK);
    }
};

QuicWireTestSuite g_quicWireTestSuite;

} // namespace
