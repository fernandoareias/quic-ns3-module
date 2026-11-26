/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 */

#ifndef QUICHEADER_H
#define QUICHEADER_H

#include "quic-connection-id.h"
#include "quic-wire.h"

#include "ns3/buffer.h"
#include "ns3/header.h"
#include "ns3/sequence-number.h"

#include <stdint.h>
#include <vector>

namespace ns3
{

/**
 * @ingroup quic
 * The header of a QUIC packet, as RFC 8999 and RFC 9000, Section 17 lay it out.
 *
 * A long header (Initial, 0-RTT, Handshake, Retry and Version Negotiation) carries the version and
 * the Destination and Source Connection IDs, and in Initial packets a token. Initial, 0-RTT and
 * Handshake packets then give the Length of the rest of the packet and a packet number of 1 to 4
 * bytes. A short header carries only the Destination Connection ID, whose length the receiver
 * knows, and the packet number.
 *
 * The packet number goes on the wire truncated to the number of bytes the sender chose. The header
 * of a received packet holds the truncated number until ReconstructPacketNumber() recovers the full
 * one.
 *
 * The Length field covers the packet number, the frames and the AEAD tag. The sender gives it with
 * SetPayloadSize() before the header is added to the packet.
 */
class QuicHeader : public Header
{
  public:
    /** Header form bit values. */
    typedef enum
    {
        SHORT = 0, //!< Short header
        LONG = 1   //!< Long header
    } TypeFormat_t;

    /** Packet types of the long header. */
    typedef enum
    {
        VERSION_NEGOTIATION = 0, //!< Version Negotiation
        INITIAL = 1,             //!< Initial
        RETRY = 2,               //!< Retry
        HANDSHAKE = 3,           //!< Handshake
        ZRTT_PROTECTED = 4,      //!< 0-RTT
        NONE = 5                 //!< No type (short header)
    } TypeLong_t;

    /** Key phase bit values. */
    typedef enum
    {
        PHASE_ZERO = 0, //!< Phase 0
        PHASE_ONE = 1   //!< Phase 1
    } KeyPhase_t;

    QuicHeader();
    ~QuicHeader() override;

    // Inherited from Header
    static TypeId GetTypeId(void);
    TypeId GetInstanceTypeId(void) const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize(void) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * Print a header into an output stream.
     *
     * @param os output stream.
     * @param tc the header.
     * @return the stream.
     */
    friend std::ostream& operator<<(std::ostream& os, QuicHeader& tc);

    /** @return a description of the packet type. */
    std::string TypeToString() const;

    /**
     * Create the header of an Initial packet (RFC 9000, Section 17.2.2).
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param packetNumber the packet number.
     * @param token the token of the Initial packet, empty when there is none.
     * @return the header.
     */
    static QuicHeader CreateInitial(const QuicConnectionId& dcid,
                                    const QuicConnectionId& scid,
                                    uint32_t version,
                                    QuicPacketNumber packetNumber,
                                    const std::vector<uint8_t>& token = {});

    /**
     * Create the header of a Retry packet (RFC 9000, Section 17.2.5). The integrity tag is the
     * AEAD trailer.
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param token the Retry token.
     * @return the header.
     */
    static QuicHeader CreateRetry(const QuicConnectionId& dcid,
                                  const QuicConnectionId& scid,
                                  uint32_t version,
                                  const std::vector<uint8_t>& token);

    /**
     * Create the header of a Handshake packet (RFC 9000, Section 17.2.4).
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param packetNumber the packet number.
     * @return the header.
     */
    static QuicHeader CreateHandshake(const QuicConnectionId& dcid,
                                      const QuicConnectionId& scid,
                                      uint32_t version,
                                      QuicPacketNumber packetNumber);

    /**
     * Create the header of a 0-RTT packet (RFC 9000, Section 17.2.3).
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param packetNumber the packet number.
     * @return the header.
     */
    static QuicHeader Create0RTT(const QuicConnectionId& dcid,
                                 const QuicConnectionId& scid,
                                 uint32_t version,
                                 QuicPacketNumber packetNumber);

    /**
     * Create a Version Negotiation packet (RFC 8999, Section 6). Its connection ids are those of
     * the packet it answers, swapped.
     *
     * @param dcid the Destination Connection ID, the Source Connection ID of the client.
     * @param scid the Source Connection ID, the Destination Connection ID of the client.
     * @param supportedVersions the versions the sender supports.
     * @return the header.
     */
    static QuicHeader CreateVersionNegotiation(const QuicConnectionId& dcid,
                                               const QuicConnectionId& scid,
                                               const std::vector<uint32_t>& supportedVersions);

    /**
     * Create a short header (RFC 9000, Section 17.3). The packet number is written with the
     * fewest bytes that the peer can recover.
     *
     * @param dcid the Destination Connection ID.
     * @param packetNumber the packet number.
     * @param keyPhaseBit the key phase bit.
     * @param spinBit the spin bit.
     * @param largestAcked the largest packet number the peer acknowledged, -1 when there is none.
     * @return the header.
     */
    static QuicHeader CreateShort(const QuicConnectionId& dcid,
                                  QuicPacketNumber packetNumber,
                                  bool keyPhaseBit = QuicHeader::PHASE_ZERO,
                                  bool spinBit = false,
                                  int64_t largestAcked = -1);

    /**
     * Create the header of an Initial packet from a 32-bit packet number.
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param packetNumber the packet number.
     * @return the header.
     */
    static QuicHeader CreateInitial(const QuicConnectionId& dcid,
                                    const QuicConnectionId& scid,
                                    uint32_t version,
                                    SequenceNumber32 packetNumber)
    {
        return CreateInitial(dcid, scid, version, QuicPacketNumber(packetNumber.GetValue()));
    }

    /**
     * Create the header of a Handshake packet from a 32-bit packet number.
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param packetNumber the packet number.
     * @return the header.
     */
    static QuicHeader CreateHandshake(const QuicConnectionId& dcid,
                                      const QuicConnectionId& scid,
                                      uint32_t version,
                                      SequenceNumber32 packetNumber)
    {
        return CreateHandshake(dcid, scid, version, QuicPacketNumber(packetNumber.GetValue()));
    }

    /**
     * Create the header of a 0-RTT packet from a 32-bit packet number.
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID.
     * @param version the version.
     * @param packetNumber the packet number.
     * @return the header.
     */
    static QuicHeader Create0RTT(const QuicConnectionId& dcid,
                                 const QuicConnectionId& scid,
                                 uint32_t version,
                                 SequenceNumber32 packetNumber)
    {
        return Create0RTT(dcid, scid, version, QuicPacketNumber(packetNumber.GetValue()));
    }

    /**
     * Create a short header from a 32-bit packet number.
     *
     * @param dcid the Destination Connection ID.
     * @param packetNumber the packet number.
     * @param keyPhaseBit the key phase bit.
     * @param spinBit the spin bit.
     * @param largestAcked the largest packet number the peer acknowledged, -1 when there is none.
     * @return the header.
     */
    static QuicHeader CreateShort(const QuicConnectionId& dcid,
                                  SequenceNumber32 packetNumber,
                                  bool keyPhaseBit = QuicHeader::PHASE_ZERO,
                                  bool spinBit = false,
                                  int64_t largestAcked = -1)
    {
        return CreateShort(dcid,
                           QuicPacketNumber(packetNumber.GetValue()),
                           keyPhaseBit,
                           spinBit,
                           largestAcked);
    }

    /** @return the Destination Connection ID. */
    QuicConnectionId GetDestinationConnectionId() const;

    /** @return the Source Connection ID, empty in a short header. */
    QuicConnectionId GetSourceConnectionId() const;

    /**
     * Set the connection ids.
     *
     * @param dcid the Destination Connection ID.
     * @param scid the Source Connection ID, ignored in a short header.
     */
    void SetConnectionIds(const QuicConnectionId& dcid, const QuicConnectionId& scid);

    /**
     * @return the packet number: the full number of a packet to send, the truncated number of a
     * received packet until ReconstructPacketNumber() is called.
     */
    QuicPacketNumber GetPacketNumber() const;

    /** @return the number of bytes of the packet number on the wire, from 1 to 4. */
    uint8_t GetPacketNumberLength() const;

    /**
     * Set the packet number, keeping the number of bytes on the wire.
     *
     * @param packetNumber the packet number.
     */
    void SetPacketNumber(QuicPacketNumber packetNumber);

    /**
     * Set the number of bytes of the packet number on the wire.
     *
     * @param length from 1 to 4.
     */
    void SetPacketNumberLength(uint8_t length);

    /**
     * Recover the full packet number of a received packet (RFC 9000, Appendix A.3).
     *
     * @param largestReceived the largest packet number received in the packet number space, -1
     * when there is none.
     */
    void ReconstructPacketNumber(int64_t largestReceived);

    /**
     * Set the bytes that the packet carries after its packet number: frames and AEAD tag. This is
     * what the Length field of a long header gives, together with the packet number.
     *
     * @param size number of bytes.
     */
    void SetPayloadSize(uint32_t size);

    /** @return the bytes after the packet number, known for a long header that was read. */
    uint32_t GetPayloadSize() const;

    /** @return the version of a long header. */
    uint32_t GetVersion() const;

    /**
     * Set the version of a long header.
     *
     * @param version the version.
     */
    void SetVersion(uint32_t version);

    /** @return the token of an Initial packet or the Retry token. */
    const std::vector<uint8_t>& GetToken() const;

    /** @return the versions listed by a Version Negotiation packet. */
    const std::vector<uint32_t>& GetSupportedVersions() const;

    /** @return the key phase bit of a short header. */
    bool GetKeyPhaseBit() const;

    /**
     * Set the key phase bit.
     *
     * @param keyPhaseBit the bit.
     */
    void SetKeyPhaseBit(bool keyPhaseBit);

    /** @return the spin bit of a short header. */
    bool GetSpinBit() const;

    /**
     * Set the spin bit.
     *
     * @param spinBit the bit.
     */
    void SetSpinBit(bool spinBit);

    /**
     * Set the length of the Destination Connection ID that Deserialize() reads from a short
     * header, which the header itself does not give. The default is 8 bytes.
     *
     * @param length number of bytes, at most 20.
     */
    void SetShortHeaderConnectionIdLength(uint8_t length);

    /**
     * @return false when the bytes read are not a header of this version: the Fixed Bit is zero, a
     * reserved bit is set, a field does not fit in the packet or a connection id is too long.
     */
    bool IsValid() const;

    /** @return the form bit. */
    uint8_t GetFormat() const;

    /** @return true for a short header. */
    bool IsShort() const;

    /** @return true for a long header. */
    bool IsLong() const
    {
        return !IsShort();
    }

    /** @return true for a Version Negotiation packet. */
    bool IsVersionNegotiation() const;

    /** @return true for an Initial packet. */
    bool IsInitial() const;

    /** @return true for a Retry packet. */
    bool IsRetry() const;

    /** @return true for a Handshake packet. */
    bool IsHandshake() const;

    /** @return true for a 0-RTT packet. */
    bool IsORTT() const;

    /**
     * @return the packet type that decides which frames the packet may carry. Version Negotiation
     * and Retry packets carry no frames: asking for their type is an error.
     */
    QuicPacketType GetPacketType() const;

    /** @return true when the packet has a packet number: every packet but Version Negotiation and
     * Retry. */
    bool HasPacketNumber() const;

    /**
     * @return true when the packet ends with a 16-byte tag: the AEAD tag of a protected packet or
     * the integrity tag of Retry. Only Version Negotiation has none.
     */
    bool HasAeadTag() const;

    /** @return true for a long header. */
    bool HasVersion() const;

    /**
     * @param lhs a header.
     * @param rhs another header.
     * @return true when every field of both headers is equal.
     */
    friend bool operator==(const QuicHeader& lhs, const QuicHeader& rhs);

  private:
    /** @return the packet type bits of the first byte of a long header, for the version. */
    uint8_t LongTypeBits() const;

    /** @return the bytes of the Length field of a long header. */
    uint32_t LengthFieldSize() const;

    bool m_form;                      //!< Form bit
    bool m_spinBit;                   //!< Spin bit (RFC 9000, Section 17.3.1)
    bool m_k;                         //!< Key phase bit
    uint8_t m_type;                   //!< Packet type of a long header
    uint8_t m_pnLength;               //!< Bytes of the packet number on the wire
    QuicConnectionId m_dcid;          //!< Destination Connection ID
    QuicConnectionId m_scid;          //!< Source Connection ID
    QuicPacketNumber m_packetNumber;  //!< Packet number
    uint32_t m_version;               //!< Version of a long header
    uint32_t m_payloadSize;           //!< Bytes after the packet number: frames and AEAD tag
    std::vector<uint8_t> m_token;     //!< Token of an Initial packet or Retry
    std::vector<uint32_t> m_versions; //!< Versions of a Version Negotiation packet
    uint8_t m_shortCidLength;         //!< Destination Connection ID length of a short header
    bool m_valid;                     //!< The bytes read form a valid header
};

} // namespace ns3

#endif /* QUICHEADER_H */
