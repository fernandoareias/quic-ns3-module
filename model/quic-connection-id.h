/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_CONNECTION_ID_H
#define QUIC_CONNECTION_ID_H

#include "ns3/buffer.h"

#include <array>
#include <cstdint>
#include <functional>
#include <iosfwd>

namespace ns3
{

/**
 * @ingroup quic
 * A QUIC connection id: from 0 to 20 bytes that name one end of a connection (RFC 9000,
 * Sections 5.1 and 17.2).
 *
 * An id compares by its bytes, and ids of the same length compare as the big-endian number they
 * hold. A default constructed id is empty (zero bytes).
 */
class QuicConnectionId
{
  public:
    /** Longest id of QUIC version 1 and 2 (RFC 9000, Section 17.2). */
    static constexpr uint8_t MAX_LENGTH = 20;

    /** Create an empty id. */
    QuicConnectionId() = default;

    /**
     * Create an id from bytes.
     *
     * @param bytes the bytes.
     * @param length number of bytes, at most MAX_LENGTH.
     */
    QuicConnectionId(const uint8_t* bytes, uint8_t length);

    /**
     * Create an 8-byte id that holds a number, most significant byte first.
     *
     * @param value the number.
     * @return the id.
     */
    static QuicConnectionId FromUint64(uint64_t value);

    /**
     * Read an id from a buffer.
     *
     * @param i the position to read from, moved past the bytes read.
     * @param length number of bytes to read, at most MAX_LENGTH.
     * @return the id.
     */
    static QuicConnectionId Deserialize(Buffer::Iterator& i, uint8_t length);

    /**
     * Write the bytes of the id, without a length.
     *
     * @param i the position to write at, moved past the bytes written.
     */
    void Serialize(Buffer::Iterator& i) const;

    /** @return the number of bytes. */
    uint8_t GetLength() const
    {
        return m_length;
    }

    /** @return true when the id has no bytes. */
    bool IsEmpty() const
    {
        return m_length == 0;
    }

    /** @return the bytes of the id. */
    const uint8_t* GetBytes() const
    {
        return m_bytes.data();
    }

    /**
     * @return the first 8 bytes of the id as a big-endian number (fewer when the id is shorter).
     */
    uint64_t ToUint64() const;

    /**
     * @param other another id.
     * @return true when both ids have the same bytes.
     */
    bool operator==(const QuicConnectionId& other) const;

    /**
     * @param other another id.
     * @return true when the ids differ.
     */
    bool operator!=(const QuicConnectionId& other) const
    {
        return !(*this == other);
    }

    /**
     * @param other another id.
     * @return true when this id sorts before the other: by bytes, then by length.
     */
    bool operator<(const QuicConnectionId& other) const;

  private:
    std::array<uint8_t, MAX_LENGTH> m_bytes{}; //!< the bytes, zero after the length
    uint8_t m_length{0};                       //!< number of bytes of the id
};

/**
 * Print an id as hexadecimal digits.
 *
 * @param os the output stream.
 * @param cid the id.
 * @return the stream.
 */
std::ostream& operator<<(std::ostream& os, const QuicConnectionId& cid);

} // namespace ns3

#endif /* QUIC_CONNECTION_ID_H */
