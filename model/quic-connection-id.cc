/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-connection-id.h"

#include "ns3/assert.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <ostream>

namespace ns3
{

QuicConnectionId::QuicConnectionId(const uint8_t* bytes, uint8_t length)
    : m_length(length)
{
    NS_ASSERT_MSG(length <= MAX_LENGTH, "a connection id has at most 20 bytes, got " << +length);
    if (length > 0)
    {
        std::memcpy(m_bytes.data(), bytes, length);
    }
}

QuicConnectionId
QuicConnectionId::FromUint64(uint64_t value)
{
    uint8_t bytes[8];
    for (int k = 0; k < 8; ++k)
    {
        bytes[k] = static_cast<uint8_t>(value >> (8 * (7 - k)));
    }
    return QuicConnectionId(bytes, 8);
}

QuicConnectionId
QuicConnectionId::Deserialize(Buffer::Iterator& i, uint8_t length)
{
    uint8_t bytes[MAX_LENGTH];
    NS_ASSERT_MSG(length <= MAX_LENGTH, "a connection id has at most 20 bytes, got " << +length);
    for (uint8_t k = 0; k < length; ++k)
    {
        bytes[k] = i.ReadU8();
    }
    return QuicConnectionId(bytes, length);
}

void
QuicConnectionId::Serialize(Buffer::Iterator& i) const
{
    for (uint8_t k = 0; k < m_length; ++k)
    {
        i.WriteU8(m_bytes[k]);
    }
}

uint64_t
QuicConnectionId::ToUint64() const
{
    uint64_t value = 0;
    for (uint8_t k = 0; k < std::min<uint8_t>(m_length, 8); ++k)
    {
        value = (value << 8) | m_bytes[k];
    }
    return value;
}

bool
QuicConnectionId::operator==(const QuicConnectionId& other) const
{
    return m_length == other.m_length &&
           std::memcmp(m_bytes.data(), other.m_bytes.data(), m_length) == 0;
}

bool
QuicConnectionId::operator<(const QuicConnectionId& other) const
{
    const int order =
        std::memcmp(m_bytes.data(), other.m_bytes.data(), std::min(m_length, other.m_length));
    if (order != 0)
    {
        return order < 0;
    }
    return m_length < other.m_length;
}

std::ostream&
operator<<(std::ostream& os, const QuicConnectionId& cid)
{
    const std::ios_base::fmtflags flags = os.flags();
    const char fill = os.fill('0');
    os << std::hex;
    for (uint8_t k = 0; k < cid.GetLength(); ++k)
    {
        os << std::setw(2) << +cid.GetBytes()[k];
    }
    os.fill(fill);
    os.flags(flags);
    return os;
}

} // namespace ns3
