/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_TLS_EMULATOR_H
#define QUIC_TLS_EMULATOR_H

#include "quic-transport-parameters.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ns3
{

/**
 * @ingroup quic
 *
 * The sizes of the TLS 1.3 handshake messages of a deployment. The messages the emulator builds
 * have the framing of RFC 8446 (a type byte and a 24 bit length) and, inside the hello messages and
 * EncryptedExtensions, a real list of extensions, among them the QUIC transport parameters
 * (RFC 9001, Section 8.2) and ALPN (RFC 7301). The rest of each message is filler, so the bytes
 * that travel in CRYPTO frames have the sizes of a real handshake without any cryptography.
 *
 * The sizes of the ecdsa and rsa profiles were measured with `openssl s_server` and `s_client -msg`
 * (OpenSSL 3.0, TLS 1.3, a self-signed certificate); the pq-hybrid profile adds the key shares of
 * X25519MLKEM768.
 */
struct QuicTlsProfile
{
    std::string name{"ecdsa"};          //!< name of the profile
    uint32_t clientHelloBody{233};      //!< ClientHello bytes without ALPN and transport parameters
    uint32_t serverHelloBody{90};       //!< ServerHello bytes
    uint32_t certificateBytes{392};     //!< bytes of one DER certificate
    uint32_t certificateVerifyBody{79}; //!< CertificateVerify bytes
    uint32_t finishedBody{52};          //!< Finished bytes
    uint32_t ticketBody{240};           //!< NewSessionTicket bytes
    uint32_t chainLength{1};            //!< certificates in the chain the server sends
    bool clientAuth{false};             //!< the server asks for a certificate of the client

    /** @return the profile of a server with an ECDSA P-256 certificate. */
    static QuicTlsProfile Ecdsa();

    /** @return the profile of a server with an RSA 2048 certificate. */
    static QuicTlsProfile Rsa();

    /** @return the profile of a hybrid post-quantum key exchange with an ECDSA certificate. */
    static QuicTlsProfile PqHybrid();

    /**
     * Look a profile up by name.
     *
     * @param name "ecdsa", "rsa", "pq-hybrid", or one of them followed by "+mtls".
     * @param profile the profile, set when the name is known.
     * @return true when the name is known.
     */
    static bool FromName(const std::string& name, QuicTlsProfile& profile);
};

/** The types of handshake message (RFC 8446, Section 4). */
enum QuicTlsMessageType : uint8_t
{
    TLS_CLIENT_HELLO = 1,
    TLS_SERVER_HELLO = 2,
    TLS_NEW_SESSION_TICKET = 4,
    TLS_ENCRYPTED_EXTENSIONS = 8,
    TLS_CERTIFICATE = 11,
    TLS_CERTIFICATE_REQUEST = 13,
    TLS_CERTIFICATE_VERIFY = 15,
    TLS_FINISHED = 20
};

/** The extension numbers the emulator reads. */
constexpr uint16_t QUIC_TLS_EXT_ALPN = 16;
constexpr uint16_t QUIC_TLS_EXT_TRANSPORT_PARAMETERS = 0x39;
constexpr uint16_t QUIC_TLS_EXT_PRE_SHARED_KEY = 41;

/**
 * @ingroup quic
 *
 * Builds the handshake messages. Each function returns the bytes of the messages of a flight, one
 * after the other, as they go in the CRYPTO frames of one encryption level.
 */
class QuicTlsEmulator
{
  public:
    /**
     * @param profile the sizes.
     * @param tp the transport parameters of the client.
     * @param alpn the application protocols the client offers.
     * @param ticket the identity of a session ticket to resume with, 0 for none (the
     *        pre_shared_key extension carries it).
     * @return a ClientHello message.
     */
    static std::vector<uint8_t> ClientHello(const QuicTlsProfile& profile,
                                            const QuicTransportParameters& tp,
                                            const std::vector<std::string>& alpn,
                                            uint64_t ticket);

    /**
     * @param profile the sizes.
     * @return a ServerHello message.
     */
    static std::vector<uint8_t> ServerHello(const QuicTlsProfile& profile);

    /**
     * The messages the server sends in Handshake packets: EncryptedExtensions, a
     * CertificateRequest when the profile asks for client authentication, Certificate,
     * CertificateVerify and Finished.
     *
     * @param profile the sizes.
     * @param tp the transport parameters of the server.
     * @param alpn the application protocol the server chose.
     * @return the messages.
     */
    static std::vector<uint8_t> ServerFlight(const QuicTlsProfile& profile,
                                             const QuicTransportParameters& tp,
                                             const std::string& alpn);

    /**
     * The messages the client sends in Handshake packets: Certificate and CertificateVerify when
     * the server asked for a certificate, and Finished.
     *
     * @param profile the sizes.
     * @return the messages.
     */
    static std::vector<uint8_t> ClientFlight(const QuicTlsProfile& profile);

    /**
     * @param profile the sizes.
     * @param ticket the identity of the ticket, which the ticket itself starts with.
     * @return a NewSessionTicket message that allows early data.
     */
    static std::vector<uint8_t> NewSessionTicket(const QuicTlsProfile& profile, uint64_t ticket);
};

/**
 * @ingroup quic
 *
 * Reads the handshake messages out of the bytes of a CRYPTO stream.
 */
class QuicTlsParser
{
  public:
    /**
     * Add the bytes that came next in the stream.
     *
     * @param data the bytes.
     */
    void Append(const std::vector<uint8_t>& data);

    /**
     * Take the next complete message.
     *
     * @param type the message type.
     * @param body the bytes of the message after its four byte header.
     * @return true when a message was complete.
     */
    bool Next(uint8_t& type, std::vector<uint8_t>& body);

    /**
     * Find an extension in the body of a ClientHello, ServerHello or EncryptedExtensions message.
     *
     * @param type the message type.
     * @param body the body.
     * @param extension the number of the extension.
     * @param data the content of the extension, set when it is found.
     * @return true when the extension is there and the message is well formed.
     */
    static bool FindExtension(uint8_t type,
                              const std::vector<uint8_t>& body,
                              uint16_t extension,
                              std::vector<uint8_t>& data);

    /**
     * Read the protocol names of an ALPN extension.
     *
     * @param data the content of the extension.
     * @param names the names, set when the extension is well formed.
     * @return true when the extension is well formed.
     */
    static bool ParseAlpn(const std::vector<uint8_t>& data, std::vector<std::string>& names);

    /**
     * Read the transport parameters of a quic_transport_parameters extension.
     *
     * @param data the content of the extension.
     * @param tp the parameters, set when they are valid.
     * @return true when the parameters are well formed (RFC 9000, Section 18).
     */
    static bool ParseTransportParameters(const std::vector<uint8_t>& data,
                                         QuicTransportParameters& tp);

    /**
     * @param body the body of a NewSessionTicket message.
     * @param ticket the identity of the ticket, set when the message is well formed.
     * @return true when the body is a well formed ticket.
     */
    static bool ParseTicket(const std::vector<uint8_t>& body, uint64_t& ticket);

    /**
     * @param data the content of the pre_shared_key extension of a ClientHello.
     * @return the identity of the ticket, 0 when there is none.
     */
    static uint64_t ParseTicketIdentity(const std::vector<uint8_t>& data);

  private:
    std::vector<uint8_t> m_buffer; //!< bytes that do not make a message yet
};

} // namespace ns3

#endif // QUIC_TLS_EMULATOR_H
