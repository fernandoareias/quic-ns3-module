/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_CRYPTO_STREAM_H
#define QUIC_CRYPTO_STREAM_H

#include <cstdint>
#include <map>
#include <vector>

namespace ns3
{

/**
 * @ingroup quic
 *
 * The byte stream that CRYPTO frames carry at one encryption level (RFC 9000, Section 19.6 and
 * RFC 9001, Section 4.1.3): data to send, tracked until it is acknowledged and sent again when a
 * packet that carried it is lost, and received data put back in order.
 */
class QuicCryptoStream
{
  public:
    /**
     * Append data to the stream.
     *
     * @param data the bytes.
     */
    void Queue(const std::vector<uint8_t>& data);

    /** @return true when there are bytes that were not sent or that have to be sent again. */
    bool HasDataToSend() const;

    /** @return true when everything that was queued was acknowledged. */
    bool AllAcked() const;

    /** @return the number of bytes queued so far. */
    uint64_t QueuedBytes() const;

    /**
     * Take the next bytes to send, the ones that were lost first.
     *
     * @param maxBytes the most to take.
     * @param offset the offset of the first byte in the stream.
     * @param data the bytes.
     * @return false when there is nothing to send.
     */
    bool NextChunk(uint32_t maxBytes, uint64_t& offset, std::vector<uint8_t>& data);

    /**
     * Note that a range was acknowledged.
     *
     * @param offset the offset of the first byte.
     * @param length the number of bytes.
     */
    void OnAcked(uint64_t offset, uint64_t length);

    /**
     * Note that a range has to be sent again, unless it was acknowledged.
     *
     * @param offset the offset of the first byte.
     * @param length the number of bytes.
     */
    void OnLost(uint64_t offset, uint64_t length);

    /**
     * Receive a CRYPTO frame.
     *
     * @param offset the offset of the data in the stream.
     * @param data the bytes.
     * @param limit the largest number of bytes of the stream that may be kept (RFC 9000, Section
     *        7.5); the frame is refused when it reaches beyond it.
     * @return false when the frame is beyond the limit.
     */
    bool OnFrame(uint64_t offset, const std::vector<uint8_t>& data, uint64_t limit);

    /** @return the bytes that came in order since the last call. */
    std::vector<uint8_t> Read();

    /** @return the number of bytes received in order so far. */
    uint64_t ReceivedOffset() const;

    /** Forget everything: the keys of the level were discarded. */
    void Discard();

  private:
    /**
     * Add a range to a set of ranges, merging those that touch.
     *
     * @param ranges the set, start -> end (exclusive).
     * @param start the start of the range.
     * @param end the end of the range, exclusive.
     */
    static void AddRange(std::map<uint64_t, uint64_t>& ranges, uint64_t start, uint64_t end);

    /**
     * @param ranges a set of ranges.
     * @param start the start of a range.
     * @param end the end of the range, exclusive.
     * @return true when the set covers the range.
     */
    static bool Covers(const std::map<uint64_t, uint64_t>& ranges, uint64_t start, uint64_t end);

    std::vector<uint8_t> m_data;                   //!< every byte queued
    uint64_t m_sent{0};                            //!< bytes sent at least once
    std::map<uint64_t, uint64_t> m_lost;           //!< ranges to send again
    std::map<uint64_t, uint64_t> m_acked;          //!< ranges acknowledged
    std::map<uint64_t, std::vector<uint8_t>> m_rx; //!< data that came out of order
    uint64_t m_readOffset{0};                      //!< bytes handed out by Read()
    std::vector<uint8_t> m_ready;                  //!< bytes in order, not read yet
};

} // namespace ns3

#endif // QUIC_CRYPTO_STREAM_H
