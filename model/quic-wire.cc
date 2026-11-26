/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-wire.h"

#include "ns3/assert.h"
#include "ns3/type-id.h"

namespace ns3
{

uint32_t
QuicVarIntLength(uint64_t value)
{
    if (value < (1ULL << 6))
    {
        return 1;
    }
    if (value < (1ULL << 14))
    {
        return 2;
    }
    if (value < (1ULL << 30))
    {
        return 4;
    }
    if (value <= QUIC_VARINT_MAX)
    {
        return 8;
    }
    return 0;
}

void
QuicWriteVarInt(Buffer::Iterator& i, uint64_t value)
{
    const uint32_t length = QuicVarIntLength(value);
    NS_ASSERT_MSG(length != 0, "a variable-length integer holds at most 2^62-1, got " << value);
    const uint8_t prefix = length == 1 ? 0x00 : length == 2 ? 0x40 : length == 4 ? 0x80 : 0xC0;
    for (uint32_t k = 0; k < length; ++k)
    {
        uint8_t byte = static_cast<uint8_t>(value >> (8 * (length - 1 - k)));
        if (k == 0)
        {
            byte |= prefix;
        }
        i.WriteU8(byte);
    }
}

uint64_t
QuicReadVarInt(Buffer::Iterator& i)
{
    const uint8_t first = i.ReadU8();
    const uint32_t length = 1U << (first >> 6);
    uint64_t value = first & 0x3F;
    for (uint32_t k = 1; k < length; ++k)
    {
        value = (value << 8) | i.ReadU8();
    }
    return value;
}

uint8_t
QuicPacketNumberLength(uint64_t packetNumber, int64_t largestAcked)
{
    const uint64_t unacked =
        (largestAcked < 0 || packetNumber <= static_cast<uint64_t>(largestAcked))
            ? packetNumber + 1
            : packetNumber - static_cast<uint64_t>(largestAcked);
    // bits needed for twice the range: ceil(log2(unacked)) + 1
    uint32_t bits = 1;
    for (uint64_t reach = 1; reach < unacked; reach <<= 1)
    {
        ++bits;
    }
    const uint8_t bytes = static_cast<uint8_t>((bits + 7) / 8);
    return bytes > 4 ? 4 : bytes;
}

uint64_t
QuicDecodePacketNumber(int64_t largest, uint64_t truncated, uint8_t length)
{
    const uint64_t expected = static_cast<uint64_t>(largest + 1);
    const uint64_t window = 1ULL << (8 * length);
    const uint64_t half = window / 2;
    const uint64_t mask = window - 1;
    const uint64_t candidate = (expected & ~mask) | truncated;
    if (candidate + half <= expected && candidate < (1ULL << 62) - window)
    {
        return candidate + window;
    }
    if (candidate > expected + half && candidate >= window)
    {
        return candidate - window;
    }
    return candidate;
}

NS_OBJECT_ENSURE_REGISTERED(QuicAeadTrailer);

TypeId
QuicAeadTrailer::GetTypeId()
{
    static TypeId tid = TypeId("ns3::QuicAeadTrailer")
                            .SetParent<Trailer>()
                            .SetGroupName("Quic")
                            .AddConstructor<QuicAeadTrailer>();
    return tid;
}

TypeId
QuicAeadTrailer::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
QuicAeadTrailer::Print(std::ostream& os) const
{
    os << "AEAD tag of " << QUIC_AEAD_TAG_SIZE << " bytes";
}

uint32_t
QuicAeadTrailer::GetSerializedSize() const
{
    return QUIC_AEAD_TAG_SIZE;
}

void
QuicAeadTrailer::Serialize(Buffer::Iterator end) const
{
    end.Prev(QUIC_AEAD_TAG_SIZE);
    for (uint32_t k = 0; k < QUIC_AEAD_TAG_SIZE; ++k)
    {
        end.WriteU8(0);
    }
}

uint32_t
QuicAeadTrailer::Deserialize(Buffer::Iterator end)
{
    return QUIC_AEAD_TAG_SIZE;
}

} // namespace ns3
