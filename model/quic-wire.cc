/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-wire.h"

#include "ns3/assert.h"

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

} // namespace ns3
