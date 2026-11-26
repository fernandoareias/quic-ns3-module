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
#include "ns3/sequence-number.h"
#include "ns3/trailer.h"

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
 * Packet numbers are numbers of at most 62 bits (RFC 9000, Section 12.3). They compare and count as
 * SequenceNumber does for TCP, modulo 2^62.
 */
typedef SequenceNumber<uint64_t, 62> QuicPacketNumber;

/** The packet types that decide which frames a packet may carry (RFC 9000, Section 12.4). */
enum class QuicPacketType : uint8_t
{
    INITIAL,   //!< Initial packet
    ZERO_RTT,  //!< 0-RTT packet
    HANDSHAKE, //!< Handshake packet
    ONE_RTT    //!< short header packet
};

/** QUIC version 2 (RFC 9369, Section 3.1). */
constexpr uint32_t QUIC_VERSION_2 = 0x6b3343cf;

/** Size of the AEAD tag that every protected packet ends with (RFC 9001, Section 5.2). */
constexpr uint32_t QUIC_AEAD_TAG_SIZE = 16;

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

/**
 * Number of bytes to encode a packet number so that the receiver can recover it (RFC 9000,
 * Appendix A.2): enough for twice the range of packets that are not yet acknowledged.
 *
 * @param packetNumber the packet number being sent.
 * @param largestAcked the largest packet number the peer acknowledged, or -1 when there is none.
 * @return 1, 2, 3 or 4.
 */
uint8_t QuicPacketNumberLength(uint64_t packetNumber, int64_t largestAcked);

/**
 * Recover a full packet number from its truncated form (RFC 9000, Appendix A.3).
 *
 * @param largest the largest packet number received so far in the packet number space, or -1 when
 * there is none.
 * @param truncated the truncated packet number of the packet.
 * @param length number of bytes of the truncated packet number, from 1 to 4.
 * @return the packet number.
 */
uint64_t QuicDecodePacketNumber(int64_t largest, uint64_t truncated, uint8_t length);

/**
 * @ingroup quic
 * The AEAD tag at the end of a protected packet. The module does not encrypt: the tag stands for
 * the bytes a real endpoint would add, so that packets have their real size.
 */
class QuicAeadTrailer : public Trailer
{
  public:
    /** @return the object TypeId. */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator end) const override;
    uint32_t Deserialize(Buffer::Iterator end) override;
};

} // namespace ns3

#endif /* QUIC_WIRE_H */
