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

#ifndef QUICSUBHEADER_H
#define QUICSUBHEADER_H

#include "quic-connection-id.h"

#include "ns3/buffer.h"
#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/sequence-number.h"

#include <stdint.h>

namespace ns3
{

/**
 * \ingroup quic
 * \brief SubHeader for the QUIC Protocol
 *
 * This class has fields corresponding to those in a QUIC subheader
 * (stream id, connection id, error code, offset, flags, etc) as well
 * as methods for serialization to and deserialization from a buffer.
 *
 * Frames and Frame Types [RFC 9000 Transport - sec. 19]
 * --------------------------------------------------------------
 *
 * The payload of all packets, after removing packet protection, consists
 * of a sequence of frames. Version Negotiation and Stateless Reset do not
 * contain frames. Payloads MUST contain at least one frame, and MAY
 * contain multiple frames and multiple frame types.
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          Frame 1 (*)                        ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          Frame 2 (*)                        ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                  ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          Frame N (*)                        ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Frames MUST fit within a single QUIC packet and MUST NOT span a QUIC
 * packet boundary. Each frame begins  with a Frame Type, indicating
 * its type, followed by additional type-dependent fields.
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Type (i)                          ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Type-Dependent Fields (*)                 ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Variable-Length Integer Encoding [RFC 9000 Transport - sec. 16]
 * --------------------------------------------------------------------------
 *
 * QUIC frames commonly use a variable-length encoding for non-negative
 * integer values. This encoding ensures that smaller integer values
 * need fewer octets to encode. The QUIC variable-length integer encoding
 * reserves the two most significant bits of the first octet to encode the
 * base 2 logarithm of the integer encoding length in octets. The integer
 * value is encoded on the remaining bits, in network byte order. This
 * means that integers are encoded on 1, 2, 4, or 8 octets and can encode
 * 6, 14, 30, or 62 bit values respectively.
 *
 *   +------+--------+-------------+-----------------------+
 *   | 2Bit | Length | Usable Bits | Range                 |
 *   +------+--------+-------------+-----------------------+
 *   | 00   | 1      | 6           | 0-63                  |
 *   |      |        |             |                       |
 *   | 01   | 2      | 14          | 0-16383               |
 *   |      |        |             |                       |
 *   | 10   | 4      | 30          | 0-1073741823          |
 *   |      |        |             |                       |
 *   | 11   | 8      | 62          | 0-4611686018427387903 |
 *   +------+--------+-------------+-----------------------+
 *
 */
class QuicSubheader : public Header
{
  public:
    /**
     * \brief Quic subheader type frame values — RFC 9000 §19
     * Frames and Frame Types [RFC 9000 Transport - sec. 19]
     */
    typedef enum
    {
        PADDING = 0x00,      //!< Padding          RFC 9000 §19.1
        PING = 0x01,         //!< Ping             RFC 9000 §19.2  (era 0x07 no draft-13)
        ACK = 0x02,          //!< Ack              RFC 9000 §19.3  (era 0x0D no draft-13)
        ACK_ECN = 0x03,      //!< Ack with ECN     RFC 9000 §19.3
        RESET_STREAM = 0x04, //!< Reset Stream     RFC 9000 §19.4  (era RST_STREAM=0x01)
        STOP_SENDING = 0x05, //!< Stop Sending     RFC 9000 §19.5  (era 0x0C no draft-13)
        CRYPTO = 0x06,       //!< Crypto           RFC 9000 §19.6
        NEW_TOKEN = 0x07,    //!< New Token        RFC 9000 §19.7
        // STREAM: base 0x08, bits OFF=0x04 LEN=0x02 FIN=0x01 (era STREAM000-STREAM111=0x10-0x17)
        STREAM = 0x08,             //!< Stream (no flags)          RFC 9000 §19.8
        STREAM_FIN = 0x09,         //!< Stream FIN                 RFC 9000 §19.8
        STREAM_LEN = 0x0a,         //!< Stream LEN                 RFC 9000 §19.8
        STREAM_LEN_FIN = 0x0b,     //!< Stream LEN+FIN             RFC 9000 §19.8
        STREAM_OFF = 0x0c,         //!< Stream OFF                 RFC 9000 §19.8
        STREAM_OFF_FIN = 0x0d,     //!< Stream OFF+FIN             RFC 9000 §19.8
        STREAM_OFF_LEN = 0x0e,     //!< Stream OFF+LEN             RFC 9000 §19.8
        STREAM_OFF_LEN_FIN = 0x0f, //!< Stream OFF+LEN+FIN         RFC 9000 §19.8
        MAX_DATA = 0x10,           //!< Max Data         RFC 9000 §19.9  (era 0x04 no draft-13)
        MAX_STREAM_DATA = 0x11,    //!< Max Stream Data  RFC 9000 §19.10 (era 0x05 no draft-13)
        MAX_STREAMS_BIDI = 0x12,   //!< Max Streams Bidi RFC 9000 §19.11 (era MAX_STREAM_ID=0x06)
        MAX_STREAMS_UNI = 0x13,    //!< Max Streams Uni  RFC 9000 §19.11
        DATA_BLOCKED = 0x14,       //!< Data Blocked     RFC 9000 §19.12 (era BLOCKED=0x08)
        STREAM_DATA_BLOCKED =
            0x15, //!< Stream Data Blocked RFC 9000 §19.13 (era STREAM_BLOCKED=0x09)
        STREAMS_BLOCKED_BIDI =
            0x16, //!< Streams Blocked Bidi RFC 9000 §19.14 (era STREAM_ID_BLOCKED=0x0A)
        STREAMS_BLOCKED_UNI = 0x17,  //!< Streams Blocked Uni RFC 9000 §19.14
        NEW_CONNECTION_ID = 0x18,    //!< New Connection Id RFC 9000 §19.15 (era 0x0B no draft-13)
        RETIRE_CONNECTION_ID = 0x19, //!< Retire Connection Id RFC 9000 §19.16
        PATH_CHALLENGE = 0x1a,       //!< Path Challenge   RFC 9000 §19.17 (era 0x0E no draft-13)
        PATH_RESPONSE = 0x1b,        //!< Path Response    RFC 9000 §19.18 (era 0x0F no draft-13)
        CONNECTION_CLOSE = 0x1c,     //!< Connection Close RFC 9000 §19.19 (era 0x02 no draft-13)
        CONNECTION_CLOSE_APP =
            0x1d,              //!< Conn Close App   RFC 9000 §19.19 (era APPLICATION_CLOSE=0x03)
        HANDSHAKE_DONE = 0x1e, //!< Handshake Done   RFC 9000 §19.20
        IMMEDIATE_ACK = 0x1f,  //!< Immediate Ack    draft-ietf-quic-ack-frequency (msquic)
        ACK_FREQUENCY = 0xaf   //!< Ack Frequency    draft-ietf-quic-ack-frequency (msquic)
    } TypeFrame_t;

    // Backward-compat aliases para código legado que ainda usa os nomes antigos do draft-13
    static const TypeFrame_t RST_STREAM = RESET_STREAM;
    static const TypeFrame_t APPLICATION_CLOSE = CONNECTION_CLOSE_APP;
    static const TypeFrame_t MAX_STREAM_ID = MAX_STREAMS_BIDI;
    static const TypeFrame_t BLOCKED = DATA_BLOCKED;
    static const TypeFrame_t STREAM_BLOCKED = STREAM_DATA_BLOCKED;
    static const TypeFrame_t STREAM_ID_BLOCKED = STREAMS_BLOCKED_BIDI;
    static const TypeFrame_t STREAM000 = STREAM;
    static const TypeFrame_t STREAM001 = STREAM_FIN;
    static const TypeFrame_t STREAM010 = STREAM_LEN;
    static const TypeFrame_t STREAM011 = STREAM_LEN_FIN;
    static const TypeFrame_t STREAM100 = STREAM_OFF;
    static const TypeFrame_t STREAM101 = STREAM_OFF_FIN;
    static const TypeFrame_t STREAM110 = STREAM_OFF_LEN;
    static const TypeFrame_t STREAM111 = STREAM_OFF_LEN_FIN;

    /**
     * \brief Quic subheader transport error codes values — RFC 9000 §20
     */
    typedef enum
    {
        NO_ERROR = 0x00,                  // RFC 9000 §20 — sem erro
        INTERNAL_ERROR = 0x01,            // Erro interno da implementação
        CONNECTION_REFUSED = 0x02,        // Servidor recusou (era SERVER_BUSY no draft-13)
        FLOW_CONTROL_ERROR = 0x03,        // Violação de flow control
        STREAM_LIMIT_ERROR = 0x04,        // Limite de streams excedido (era STREAM_ID_ERROR)
        STREAM_STATE_ERROR = 0x05,        // Frame inválido para o estado do stream
        FINAL_SIZE_ERROR = 0x06,          // Final size mudou (era FINAL_OFFSET_ERROR)
        FRAME_ENCODING_ERROR = 0x07,      // Frame malformado (era FRAME_FORMAT_ERROR)
        TRANSPORT_PARAMETER_ERROR = 0x08, // Parâmetro de transporte inválido
        CONNECTION_ID_LIMIT_ERROR =
            0x09,                      // Limite de Connection IDs (era VERSION_NEGOTIATION_ERROR)
        PROTOCOL_VIOLATION = 0x0a,     // Violação genérica de protocolo
        INVALID_TOKEN = 0x0b,          // Token inválido (era UNSOLICITED_PATH_ERROR)
        APPLICATION_ERROR = 0x0c,      // Erro da camada de aplicação
        CRYPTO_BUFFER_EXCEEDED = 0x0d, // Buffer CRYPTO excedido
        KEY_UPDATE_ERROR = 0x0e,       // Erro em Key Update (RFC 9001 §12.10)
        AEAD_LIMIT_REACHED = 0x0f,     // Limite de uso AEAD (RFC 9001 §14.7)
        NO_VIABLE_PATH = 0x10,         // Nenhum caminho viável
        CRYPTO_ERROR = 0x100 // Base para erros TLS: 0x100 | AlertDescription (RFC 9001 §4.8)
    } TransportErrorCodes_t;

    // Backward-compat aliases para código legado que usa os nomes antigos do draft-13
    static const TransportErrorCodes_t SERVER_BUSY = CONNECTION_REFUSED;
    static const TransportErrorCodes_t STREAM_ID_ERROR = STREAM_LIMIT_ERROR;
    static const TransportErrorCodes_t FINAL_OFFSET_ERROR = FINAL_SIZE_ERROR;
    static const TransportErrorCodes_t FRAME_FORMAT_ERROR = FRAME_ENCODING_ERROR;
    static const TransportErrorCodes_t VERSION_NEGOTIATION_ERROR = CONNECTION_ID_LIMIT_ERROR;
    static const TransportErrorCodes_t UNSOLICITED_PATH_ERROR = INVALID_TOKEN;
    static const TransportErrorCodes_t FRAME_ERROR = CRYPTO_ERROR;

    QuicSubheader();
    virtual ~QuicSubheader();

    // Inherited from Header
    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const;
    virtual void Print(std::ostream& os) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(Buffer::Iterator start) const;
    virtual uint32_t Deserialize(Buffer::Iterator start);

    /**
     * \brief Print a Quic subheader into an output stream
     *
     * \param os output stream
     * \param tc Quic subheader to print
     * \return The ostream passed as first argument
     */
    friend std::ostream& operator<<(std::ostream& os, QuicSubheader& tc);

    /**
     * \brief Converts the frame type flag into a human readable string description
     *
     * \return the generated string
     **/
    std::string FrameTypeToString() const;

    /**
     * \brief Converts the transport error code into a human readable string description
     *
     * \return the generated string
     **/
    std::string TransportErrorCodeToString() const;

    /**
     * \brief Write a variable-length 64-bit integer on a buffer according to the encoding standards
     *
     * \param i the buffer iterator
     * \param varInt64 the variable-length 64-bit integer
     **/
    void WriteVarInt64(Buffer::Iterator& i, uint64_t varInt64) const;

    /**
     * \brief Read a variable-length 64-bit integer from a buffer according to the encoding
     * standards
     *
     * \param i the buffer iterator
     * \return the variable-length 64-bit integer
     **/
    uint64_t ReadVarInt64(Buffer::Iterator& i);

    /**
     * \brief Get the variable-length 64-bit integer size according to the encoding standards (in
     * bits)
     *
     * \param varInt64 the variable-length 64-bit integer
     * \return the size of the variable-length 64-bit integer (in bits)
     **/
    static uint32_t GetVarInt64Size(uint64_t varInt64);

    /**
     * Create a Padding subheader
     *
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreatePadding(void);

    /**
     * Create a Max Stream Data subheader
     *
     * \param streamId the stream id of the stream being terminated
     * \param applicationErrorCode the error code that indicates why the stream is being closed
     * \param finalOffset the absolute byte offset of the end of data written on this stream by the
     * RST_STREAM sender
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateRstStream(uint64_t streamId,
                                         uint64_t applicationErrorCode,
                                         uint64_t finalOffset);

    /**
     * Create a Connection Close subheader
     *
     * \param errorCode the error code that indicates the reason for closing this connection
     * \param reasonPhrase the human-readable explanation for why the connection has been closed
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateConnectionClose(uint64_t errorCode, const char* reasonPhrase);

    /**
     * Create a Application Close subheader
     *
     * \param errorCode the error code that indicates the reason for closing this connection
     * \param reasonPhrase the human-readable explanation for why the connection has been closed
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateApplicationClose(uint64_t errorCode, const char* reasonPhrase);

    /**
     * Create a Max Data subheader
     *
     * \param maxData the maximum amount of data that can be sent on the entire connection
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateMaxData(uint64_t maxData);

    /**
     * Create a Max Stream Data subheader
     *
     * \param streamId The stream id of the stream that is affected
     * \param maxStreamData the maximum amount of data that can be sent on the identified stream
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateMaxStreamData(uint64_t streamId, uint64_t maxStreamData);

    /**
     * Create a Max Stream Id subheader
     *
     * \param maxStreamId the id of the maximum unidirectional or bidirectional peer-initiated
     * stream id for the connection
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateMaxStreamId(uint64_t maxStreamId);

    /**
     * Create a Ping subheader
     *
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreatePing(void);

    /**
     * Create a Handshake Done subheader (RFC 9000 §19.20)
     * Sent by server to signal handshake completion. No payload.
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateHandshakeDone(void);

    /**
     * Create a Blocked subheader
     *
     * \param offset the connection-level offset at which the blocking occurred
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateBlocked(uint64_t offset);

    /**
     * Create a Stream Blocked subheader
     *
     * \param streamId the stream which is flow control blocked
     * \param offset the offset of the stream at which the blocking occurred
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateStreamBlocked(uint64_t streamId, uint64_t offset);

    /**
     * Create a Stream Id Blocked subheader
     *
     * \param streamId the highest stream id that the sender was permitted to open
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateStreamIdBlocked(uint64_t streamId);

    /**
     * Create a New Connection Id subheader
     *
     * \param sequence this value starts at 0 and increases by 1 for each connection ID that is
     * provided by the server
     * \param connectionId the new connection id
     * \param statelessResetToken the 128-bit value that will be used to for a stateless reset when
     * the associated connection ID is used
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateNewConnectionId(
        uint64_t sequence,
        const QuicConnectionId& connectionId); // uint128_t statelessResetToken);

    /**
     * Create a NEW_CONNECTION_ID subheader with all its fields (RFC 9000 s19.15)
     * \param sequence the sequence number of the id
     * \param retirePriorTo ids with a lower sequence number are to be retired
     * \param connectionId the new connection id
     * \param tokenHi upper 64 bits of the stateless reset token of this id
     * \param tokenLo lower 64 bits of the stateless reset token of this id
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateNewConnectionId(uint64_t sequence,
                                               uint64_t retirePriorTo,
                                               const QuicConnectionId& connectionId,
                                               uint64_t tokenHi,
                                               uint64_t tokenLo);

    /**
     * Create a RETIRE_CONNECTION_ID subheader (RFC 9000 s19.16)
     * \param sequence the sequence number of the id to retire
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateRetireConnectionId(uint64_t sequence);

    /** \return the retire prior to field of a NEW_CONNECTION_ID frame */
    uint64_t GetRetirePriorTo() const
    {
        return m_retirePriorTo;
    }

    /** \return the upper 64 bits of the stateless reset token of a NEW_CONNECTION_ID frame */
    uint64_t GetResetTokenHi() const
    {
        return m_resetTokenHi;
    }

    /** \return the lower 64 bits of the stateless reset token of a NEW_CONNECTION_ID frame */
    uint64_t GetResetTokenLo() const
    {
        return m_resetTokenLo;
    }

    /**
     * Create a Stop Sending subheader
     *
     * \param streamId the stream id of the stream being ignored
     * \param applicationErrorCode the application-specified reason the sender is ignoring the
     * stream
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateStopSending(uint64_t streamId, uint64_t applicationErrorCode);

    /**
     * Create an ACK_FREQUENCY subheader (draft-ietf-quic-ack-frequency, as msquic)
     *
     * \param sequence the frame sequence number
     * \param ackElicitingThreshold how many ack-eliciting packets may arrive before an ACK is due
     * \param maxAckDelayUs the requested maximum ACK delay, in microseconds
     * \param reorderingThreshold the reordering threshold that makes the peer ACK at once
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateAckFrequency(uint64_t sequence,
                                            uint64_t ackElicitingThreshold,
                                            uint64_t maxAckDelayUs,
                                            uint64_t reorderingThreshold);

    /**
     * Create an IMMEDIATE_ACK subheader
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateImmediateAck(void);

    /** \return true if this is an ACK_FREQUENCY frame */
    bool IsAckFrequency() const;
    /** \return true if this is an IMMEDIATE_ACK frame */
    bool IsImmediateAck() const;

    /** \return the ACK_FREQUENCY sequence number */
    uint64_t GetAckFreqSequence() const
    {
        return m_ackFreqSeq;
    }

    /** \return the ACK_FREQUENCY ack-eliciting threshold */
    uint64_t GetAckFreqThreshold() const
    {
        return m_ackFreqThreshold;
    }

    /** \return the ACK_FREQUENCY requested maximum ack delay (us) */
    uint64_t GetAckFreqMaxDelayUs() const
    {
        return m_ackFreqMaxDelayUs;
    }

    /** \return the ACK_FREQUENCY reordering threshold */
    uint64_t GetAckFreqReordering() const
    {
        return m_ackFreqReordering;
    }

    /**
     * Create a Ack subheader
     *
     * \param largestAcknowledged the largest packet number the peer is acknowledging
     * \param ackDelay the time in microseconds that the largest acknowledged packet, was received
     * by this peer to when this ACK was sent
     * \param firstAckBlock the number of contiguous packets preceding the Largest Acknowledged that
     * are being acknowledged
     * \param gaps the vector where each field contains the number of contiguous unacknowledged
     * packets preceding the packet number one lower than the smallest in the preceding ack block
     * \param additionalAckBlocks the vector where each field contains the number of contiguous
     * acknowledged packets preceding the largest packet number
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateAck(uint64_t largestAcknowledged,
                                   uint64_t ackDelay,
                                   uint64_t firstAckBlock,
                                   std::vector<uint64_t>& gaps,
                                   std::vector<uint64_t>& additionalAckBlocks);

    /**
     * Create a Path Response subheader
     *
     * \param data the data word of the Path Challenge subheader
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreatePathChallenge(uint64_t data);

    /**
     * Create a Path Response subheader
     *
     * \param data the data word of the Path Response subheader
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreatePathResponse(uint64_t data);

    /**
     * Create a Stream subheader
     *
     * \param streamId the ID of the stream
     * \param offset the offset of the first byte of the frame in the stream
     * \param length the packet size
     * \param offBit a flag to indicate whether the offset is carried or not
     * \param lengthBit a flag to indicate whether the length is carried or not
     * \param finBit a flag to indicate the FIN bit
     * \return the generated QuicSubheader
     */
    static QuicSubheader CreateStreamSubHeader(uint64_t streamId,
                                               uint64_t offset,
                                               uint64_t length,
                                               bool offBit = false,
                                               bool lengthBit = false,
                                               bool finBit = false);

    // Getters, Setters and Controls

    /**
     * \brief Get the ack block count
     * \return The ack block count for this QuicSubheader
     */
    uint64_t GetAckBlockCount() const;

    /**
     * \brief Set the ack block count
     * \param ackBlockCount the ack block count for this QuicSubheader
     */
    void SetAckBlockCount(uint64_t ackBlockCount);

    /**
     * \brief Get the additional ack block vector
     * \return The additional ack block vector for this QuicSubheader
     */
    const std::vector<uint64_t>& GetAdditionalAckBlocks() const;

    /**
     * \brief Set the additional ack block vector
     * \param ackBlocks the additional ack block vector for this QuicSubheader
     */
    void SetAdditionalAckBlocks(const std::vector<uint64_t>& ackBlocks);

    /**
     * \brief Get the ack delay
     * \return The ack delay for this QuicSubheader
     */
    uint64_t GetAckDelay() const;

    /**
     * \brief Set the ack delay
     * \param ackDelay the ack delay for this QuicSubheader
     */
    void SetAckDelay(uint64_t ackDelay);

    /**
     * \brief Get the connection id
     * \return The connection id for this QuicSubheader
     */
    QuicConnectionId GetConnectionId() const;

    /**
     * \brief Set the connection id
     * \param connectionId the connection id for this QuicSubheader
     */
    void SetConnectionId(const QuicConnectionId& connectionId);

    /**
     * \brief Get the data word
     * \return The data word for this QuicSubheader
     */
    uint64_t GetData() const;

    /**
     * \brief Set the data word
     * \param data the data word for this QuicSubheader
     */
    void SetData(uint64_t data);

    /**
     * \brief Get the error code
     * \return The data word for this QuicSubheader
     */
    uint64_t GetErrorCode() const;

    /**
     * \brief Set the error code
     * \param errorCode the error code for this QuicSubheader
     */
    void SetErrorCode(uint64_t errorCode);

    /**
     * \brief Get the frame type
     * \return The frame type for this QuicSubheader
     */
    uint64_t GetFrameType() const;

    /**
     * \brief Set the frame type
     * \param frameType the frame type for this QuicSubheader
     */
    void SetFrameType(uint64_t frameType);

    /**
     * \brief Get the gap vector
     * \return The gap vector for this QuicSubheader
     */
    const std::vector<uint64_t>& GetGaps() const;

    /**
     * \brief Set the gap vector
     * \param gaps the gap for this QuicSubheader
     */
    void SetGaps(const std::vector<uint64_t>& gaps);

    /**
     * \brief Get the largest acknowledged
     * \return The largest acknowledged for this QuicSubheader
     */
    uint64_t GetLargestAcknowledged() const;

    /**
     * \brief Set the largest acknowledged
     * \param largestAcknowledged the largest acknowledged for this QuicSubheader
     */
    void SetLargestAcknowledged(uint64_t largestAcknowledged);

    /**
     * \brief Get the ECT(0) count from an ACK_ECN frame (RFC 9000 §19.3.2)
     * \return m_ect0Count
     */
    uint64_t GetEct0Count() const;

    /**
     * Make an ACK frame an ACK frame with ECN counts (RFC 9000, Section 19.3.2).
     *
     * @param ect0 the number of packets received with ECT(0).
     * @param ect1 the number of packets received with ECT(1).
     * @param ce the number of packets received with ECN-CE.
     */
    void SetEcnCounts(uint64_t ect0, uint64_t ect1, uint64_t ce);

    /**
     * \brief Get the ECT(1) count from an ACK_ECN frame (RFC 9000 §19.3.2)
     * \return m_ect1Count
     */
    uint64_t GetEct1Count() const;

    /**
     * \brief Get the ECN-CE count from an ACK_ECN frame (RFC 9000 §19.3.2)
     * \return m_ecnCeCount
     */
    uint64_t GetEcnCeCount() const;

    /**
     * \brief Get the length
     * \return The length for this QuicSubheader
     */
    uint64_t GetLength() const;

    /**
     * \brief Set the length
     * \param length the length for this QuicSubheader
     */
    void SetLength(uint64_t length);

    /**
     * \brief Get the max data
     * \return The max data for this QuicSubheader
     */
    uint64_t GetMaxData() const;

    /**
     * \brief Set the max data
     * \param maxData the max data for this QuicSubheader
     */
    void SetMaxData(uint64_t maxData);

    /**
     * \brief Get the max stream data
     * \return The max stream data for this QuicSubheader
     */
    uint64_t GetMaxStreamData() const;

    /**
     * \brief Set the max stream data
     * \param maxStreamData the max stream data for this QuicSubheader
     */
    void SetMaxStreamData(uint64_t maxStreamData);

    /**
     * \brief Get the max stream id
     * \return The max stream id for this QuicSubheader
     */
    uint64_t GetMaxStreamId() const;

    /**
     * \brief Set the max stream id
     * \param maxStreamId the max stream id for this QuicSubheader
     */
    void SetMaxStreamId(uint64_t maxStreamId);

    /**
     * \brief Get the offset
     * \return The offset for this QuicSubheader
     */
    uint64_t GetOffset() const;

    /**
     * \brief Set the offset
     * \param offset the offset for this QuicSubheader
     */
    void SetOffset(uint64_t offset);

    /**
     * \brief Get the reason phrase vector
     * \return The reason phrase vector for this QuicSubheader
     */
    const std::vector<uint8_t>& GetReasonPhrase() const;

    /**
     * \brief Set the reason phrase vector
     * \param reasonPhrase the reason phrase vector for this QuicSubheader
     */
    void SetReasonPhrase(const std::vector<uint8_t>& reasonPhrase);

    /**
     * \brief Get the reason phrase length
     * \return The reason phrase length for this QuicSubheader
     */
    uint64_t GetReasonPhraseLength() const;

    /**
     * \brief Set the reason phrase length
     * \param reasonPhraseLength the reason phrase length for this QuicSubheader
     */
    void SetReasonPhraseLength(uint64_t reasonPhraseLength);

    /**
     * \brief Get the sequence
     * \return The sequence for this QuicSubheader
     */
    uint64_t GetSequence() const;

    /**
     * \brief Set the sequence
     * \param sequence the sequence for this QuicSubheader
     */
    void SetSequence(uint64_t sequence);

    /**
     * \brief Get the stream Id
     * \return The stream Id for this QuicSubheader
     */
    uint64_t GetStreamId() const;

    /**
     * \brief Set the stream Id
     * \param streamId the stream Id for this QuicSubheader
     */
    void SetStreamId(uint64_t streamId);

    /**
     * \brief Get the first ack block
     * \return The first ack block for this QuicSubheader
     */
    uint64_t GetFirstAckBlock() const;

    /**
     * \brief Set the first ack block
     * \param firstAckBlock the first ack block for this QuicSubheader
     */
    void SetFirstAckBlock(uint64_t firstAckBlock);

    // TODO: Implement Stateless Reset Token functionality
    // uint128_t getStatelessResetToken() const;
    // void SetStatelessResetToken(uint128_t statelessResetToken);

    /**
     * \brief Check if the subheader is Padding
     * \return true if the subheader is Padding, false otherwise
     */
    bool IsPadding() const;

    /**
     * \brief Check if the subheader is Rst Stream
     * \return true if the subheader is Rst Stream, false otherwise
     */
    bool IsRstStream() const;

    /**
     * \brief Check if the subheader is Connection Close
     * \return true if the subheader is Connection Close, false otherwise
     */
    bool IsConnectionClose() const;

    /**
     * \brief Check if the subheader is Application Close
     * \return true if the subheader is Application Close, false otherwise
     */
    bool IsApplicationClose() const;

    /**
     * \brief Check if the subheader is Max Data
     * \return true if the subheader is Max Data, false otherwise
     */
    bool IsMaxData() const;

    /**
     * \brief Check if the subheader is Max Stream Data
     * \return true if the subheader is Max Stream Data, false otherwise
     */
    bool IsMaxStreamData() const;

    /**
     * \brief Check if the subheader is Max Stream Id
     * \return true if the subheader is Max Stream Id, false otherwise
     */
    bool IsMaxStreamId() const;

    /**
     * \brief Check if the subheader is Ping
     * \return true if the subheader is Ping, false otherwise
     */
    bool IsPing() const;

    /**
     * \brief Check if the subheader is Blocked
     * \return true if the subheader is Blocked, false otherwise
     */
    bool IsBlocked() const;

    /**
     * \brief Check if the subheader is Stream Blocked
     * \return true if the subheader is Stream Blocked, false otherwise
     */
    bool IsStreamBlocked() const;

    /**
     * \brief Check if the subheader is Stream Id Blocked
     * \return true if the subheader is Stream Id Blocked, false otherwise
     */
    bool IsStreamIdBlocked() const;

    /**
     * \brief Check if the subheader is New Connection Id
     * \return true if the subheader is New Connection Id, false otherwise
     */
    bool IsNewConnectionId() const;

    /**
     * \brief Check if the subheader is Stop Sending
     * \return true if the subheader is Stop Sending, false otherwise
     */
    bool IsStopSending() const;

    /**
     * \brief Check if the subheader is Ack
     * \return true if the subheader is Ack, false otherwise
     */
    bool IsAck() const;

    /**
     * \brief Check if the subheader is Path Challenge
     * \return true if the subheader is Path Challenge, false otherwise
     */
    bool IsPathChallenge() const;

    /**
     * \brief Check if the subheader is Path Response
     * \return true if the subheader is Path Response, false otherwise
     */
    bool IsPathResponse() const;

    /**
     * \brief Check if the subheader is Stream
     * \return true if the subheader is Stream, false otherwise
     */
    bool IsStream() const;

    /**
     * \brief Check if the subheader is Stream and the FIN bit is true
     * \return true if the subheader is Stream and the FIN bit is true, false otherwise
     */
    bool IsStreamFin() const;

    /**
     * Comparison operator
     * \param lhs left operand
     * \param rhs right operand
     * \return true if the operands are equal
     */
    friend bool operator==(const QuicSubheader& lhs, const QuicSubheader& rhs);

    /**
     * \brief Calculates the subheader length (in words)
     *
     * Given the standard size of the subheader, the method checks for options
     * and calculates the real length (in words).
     *
     * \return subheader length in 4-byte words
     */
    uint32_t CalculateSubHeaderLength() const;

    /**
     * @return false when the bytes read are not a well formed frame: it is truncated, a field
     * does not fit, its type is not defined or it is not in its shortest form.
     */
    bool IsValid() const
    {
        return m_valid;
    }

    /**
     * @return the transport error code to close the connection with when the frame read is not
     * valid: FRAME_ENCODING_ERROR, or PROTOCOL_VIOLATION for a frame type that is longer than it
     * has to be. Zero when the frame is valid.
     */
    uint64_t GetParseError() const
    {
        return m_parseError;
    }

    /**
     * @return true when the length of the data that follows the frame is in the frame: a CRYPTO
     * frame, and a STREAM frame with the LEN bit. A STREAM frame without it runs to the end of
     * the packet.
     */
    bool HasLengthField() const;

    /**
     * The number of bytes of data that follow the frame in the packet: the Length of a CRYPTO
     * frame or of a STREAM frame that has one, the rest of the packet for a STREAM frame without
     * a Length, and zero for the other frames.
     *
     * @param remaining the bytes left in the packet after the frame.
     * @return the bytes of data.
     */
    uint64_t GetPayloadLength(uint64_t remaining) const;

    /**
     * Create a CRYPTO frame (RFC 9000, Section 19.6). The data follows the frame in the packet.
     *
     * @param offset the offset of the data in the CRYPTO stream of the encryption level.
     * @param length the number of bytes of data.
     * @return the frame.
     */
    static QuicSubheader CreateCrypto(uint64_t offset, uint64_t length);

    /**
     * Create a NEW_TOKEN frame (RFC 9000, Section 19.7).
     *
     * @param token the token, not empty.
     * @return the frame.
     */
    static QuicSubheader CreateNewToken(const std::vector<uint8_t>& token);

    /** @return the token of a NEW_TOKEN frame. */
    const std::vector<uint8_t>& GetToken() const
    {
        return m_token;
    }

    /** @return true for a CRYPTO frame. */
    bool IsCrypto() const
    {
        return m_frameType == CRYPTO;
    }

    /** @return true for a NEW_TOKEN frame. */
    bool IsNewToken() const
    {
        return m_frameType == NEW_TOKEN;
    }

  private:
    /**
     * Write the fields of the frame to a writer, which counts them or writes them to a buffer.
     *
     * @param writer the writer.
     */
    template <typename Writer>
    void Encode(Writer& writer) const;

    /**
     * \brief The ACK ranges as RFC 9000 s19.3.1 writes them: first range length, then (gap, length)
     * pairs
     * \return the values in wire order, after the range count
     */
    std::vector<uint64_t> AckWireRanges() const;

    uint64_t m_frameType; //!< Frame type
    uint64_t m_streamId;  //!< Stream id
    uint64_t m_errorCode; //!< Error code
    uint64_t m_triggerFrameType{
        0};            //!< CONNECTION_CLOSE: the frame type that triggered the error (0 = unknown)
    uint64_t m_offset; //!< Offset
    uint64_t m_reasonPhraseLength;       //!< Reason phrase length
    std::vector<uint8_t> m_reasonPhrase; //!< Reason phrase
    uint64_t m_maxData;                  //!< Max data limit
    uint64_t m_retirePriorTo{0};         //!< NEW_CONNECTION_ID retire prior to
    uint64_t m_resetTokenHi{0};          //!< NEW_CONNECTION_ID stateless reset token, upper 64 bits
    uint64_t m_resetTokenLo{0};          //!< NEW_CONNECTION_ID stateless reset token, lower 64 bits
    uint64_t m_ackFreqSeq{0};            //!< ACK_FREQUENCY sequence number
    uint64_t m_ackFreqThreshold{2};      //!< ACK_FREQUENCY ack-eliciting threshold
    uint64_t m_ackFreqMaxDelayUs{25000}; //!< ACK_FREQUENCY requested max ack delay (us)
    uint64_t m_ackFreqReordering{1};     //!< ACK_FREQUENCY reordering threshold
    uint64_t m_maxStreamData;            //!< Max stream data limit
    uint64_t m_maxStreamId;              //!< Max stream id limit
    uint64_t m_sequence;                 //!< Sequence
    QuicConnectionId m_connectionId;     //!< Connection id
    // uint128_t statelessResetToken;              //!< Stateless reset token
    uint64_t m_largestAcknowledged;              //!< Largest acknowledged
    uint64_t m_ackDelay;                         //!< Ack delay
    uint64_t m_ackBlockCount;                    //!< Ack block count
    uint64_t m_firstAckBlock;                    //!< First Ack block
    std::vector<uint64_t> m_additionalAckBlocks; //!< Additional ack blocks vector
    std::vector<uint64_t> m_gaps;                //!< Gaps vector
    // RFC 9002 §9.2 / RFC 9000 §19.3.2: ECN counts carried in ACK_ECN frames
    uint64_t m_ect0Count{0};      //!< ECT(0) count
    uint64_t m_ect1Count{0};      //!< ECT(1) count
    uint64_t m_ecnCeCount{0};     //!< ECN-CE count
    uint64_t m_data;              //!< Data word (8 bytes, RFC 9000 §19.17/§19.18)
    std::vector<uint8_t> m_token; //!< NEW_TOKEN: the token
    bool m_valid{true};           //!< The bytes read were a well formed frame
    uint64_t m_parseError{0};     //!< Error code for a frame that was not well formed
    uint64_t m_length;            //!< Length
};

} // namespace ns3

#endif /* QUIC_SUBHEADER_H_ */
