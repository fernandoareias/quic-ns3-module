/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-crypto-stream.h"

#include <algorithm>

namespace ns3
{

void
QuicCryptoStream::AddRange(std::map<uint64_t, uint64_t>& ranges, uint64_t start, uint64_t end)
{
    if (start >= end)
    {
        return;
    }
    auto it = ranges.lower_bound(start);
    if (it != ranges.begin())
    {
        auto prev = std::prev(it);
        if (prev->second >= start)
        {
            start = prev->first;
            end = std::max(end, prev->second);
            it = ranges.erase(prev);
        }
    }
    while (it != ranges.end() && it->first <= end)
    {
        end = std::max(end, it->second);
        it = ranges.erase(it);
    }
    ranges[start] = end;
}

bool
QuicCryptoStream::Covers(const std::map<uint64_t, uint64_t>& ranges, uint64_t start, uint64_t end)
{
    auto it = ranges.upper_bound(start);
    if (it == ranges.begin())
    {
        return false;
    }
    --it;
    return it->first <= start && it->second >= end;
}

void
QuicCryptoStream::Queue(const std::vector<uint8_t>& data)
{
    m_data.insert(m_data.end(), data.begin(), data.end());
}

bool
QuicCryptoStream::HasDataToSend() const
{
    return !m_lost.empty() || m_sent < m_data.size();
}

bool
QuicCryptoStream::AllAcked() const
{
    return Covers(m_acked, 0, m_data.size()) || m_data.empty();
}

uint64_t
QuicCryptoStream::QueuedBytes() const
{
    return m_data.size();
}

bool
QuicCryptoStream::NextChunk(uint32_t maxBytes, uint64_t& offset, std::vector<uint8_t>& data)
{
    if (maxBytes == 0)
    {
        return false;
    }
    while (!m_lost.empty())
    {
        auto it = m_lost.begin();
        const uint64_t start = it->first;
        const uint64_t end = it->second;
        m_lost.erase(it);
        if (Covers(m_acked, start, end))
        {
            continue;
        }
        const uint64_t take = std::min<uint64_t>(end - start, maxBytes);
        if (start + take < end)
        {
            m_lost[start + take] = end;
        }
        offset = start;
        data.assign(m_data.begin() + start, m_data.begin() + start + take);
        return true;
    }
    if (m_sent >= m_data.size())
    {
        return false;
    }
    const uint64_t take = std::min<uint64_t>(m_data.size() - m_sent, maxBytes);
    offset = m_sent;
    data.assign(m_data.begin() + m_sent, m_data.begin() + m_sent + take);
    m_sent += take;
    return true;
}

void
QuicCryptoStream::OnAcked(uint64_t offset, uint64_t length)
{
    AddRange(m_acked, offset, offset + length);
}

void
QuicCryptoStream::OnLost(uint64_t offset, uint64_t length)
{
    if (!Covers(m_acked, offset, offset + length))
    {
        AddRange(m_lost, offset, offset + length);
    }
}

bool
QuicCryptoStream::OnFrame(uint64_t offset, const std::vector<uint8_t>& data, uint64_t limit)
{
    if (offset + data.size() > limit)
    {
        return false;
    }
    const uint64_t end = offset + data.size();
    if (end <= m_readOffset + m_ready.size() || data.empty())
    {
        return true;
    }
    uint64_t next = m_readOffset + m_ready.size();
    if (offset > next)
    {
        auto it = m_rx.find(offset);
        if (it == m_rx.end() || it->second.size() < data.size())
        {
            m_rx[offset] = data;
        }
        return true;
    }
    m_ready.insert(m_ready.end(), data.begin() + (next - offset), data.end());
    next = m_readOffset + m_ready.size();
    while (!m_rx.empty() && m_rx.begin()->first <= next)
    {
        auto it = m_rx.begin();
        const uint64_t segEnd = it->first + it->second.size();
        if (segEnd > next)
        {
            m_ready.insert(m_ready.end(),
                           it->second.begin() + (next - it->first),
                           it->second.end());
            next = segEnd;
        }
        m_rx.erase(it);
    }
    return true;
}

std::vector<uint8_t>
QuicCryptoStream::Read()
{
    std::vector<uint8_t> out;
    out.swap(m_ready);
    m_readOffset += out.size();
    return out;
}

uint64_t
QuicCryptoStream::ReceivedOffset() const
{
    return m_readOffset + m_ready.size();
}

void
QuicCryptoStream::Discard()
{
    m_data.clear();
    m_sent = 0;
    m_lost.clear();
    m_acked.clear();
    m_rx.clear();
    m_ready.clear();
}

} // namespace ns3
