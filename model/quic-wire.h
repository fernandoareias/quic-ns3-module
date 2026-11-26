/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_WIRE_H
#define QUIC_WIRE_H

#include "ns3/buffer.h"

#include <cstdint>

/**
 * @file
 * @ingroup quic
 * Building blocks of the QUIC wire format that do not depend on a packet or frame type.
 */

namespace ns3
{

/** Largest value of a variable-length integer (RFC 9000, Section 16). */
constexpr uint64_t QUIC_VARINT_MAX = (1ULL << 62) - 1;

/**
 * Number of bytes of the shortest variable-length integer encoding of a value.
 *
 * @param value the value.
 * @return 1, 2, 4 or 8, or 0 when the value is larger than QUIC_VARINT_MAX.
 */
uint32_t QuicVarIntLength(uint64_t value);

/**
 * Write a value as a variable-length integer (RFC 9000, Section 16), in the shortest form.
 *
 * @param i the position to write at, moved past the bytes written.
 * @param value the value, at most QUIC_VARINT_MAX.
 */
void QuicWriteVarInt(Buffer::Iterator& i, uint64_t value);

/**
 * Read a variable-length integer (RFC 9000, Section 16). Non-minimal encodings are accepted.
 *
 * @param i the position to read from, moved past the bytes read.
 * @return the value.
 */
uint64_t QuicReadVarInt(Buffer::Iterator& i);

} // namespace ns3

#endif /* QUIC_WIRE_H */
