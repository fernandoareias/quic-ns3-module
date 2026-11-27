/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-tls-emulator.h"

#include "quic-wire.h"

#include "ns3/buffer.h"

#include <algorithm>

namespace ns3
{

namespace
{

/** Append a big-endian integer of some bytes. */
void
Put(std::vector<uint8_t>& out, uint64_t value, uint32_t bytes)
{
    for (uint32_t k = 0; k < bytes; ++k)
    {
        out.push_back(static_cast<uint8_t>(value >> (8 * (bytes - 1 - k))));
    }
}

/** Append zero bytes. */
void
PutZeros(std::vector<uint8_t>& out, uint32_t count)
{
    out.insert(out.end(), count, 0);
}

/** Append a message: its type, a 24 bit length and the body. */
void
PutMessage(std::vector<uint8_t>& out, uint8_t type, const std::vector<uint8_t>& body)
{
    out.push_back(type);
    Put(out, body.size(), 3);
    out.insert(out.end(), body.begin(), body.end());
}

/** Append one extension: its number, a 16 bit length and the content. */
void
PutExtension(std::vector<uint8_t>& out, uint16_t type, const std::vector<uint8_t>& data)
{
    Put(out, type, 2);
    Put(out, data.size(), 2);
    out.insert(out.end(), data.begin(), data.end());
}

/**
 * @param tp transport parameters.
 * @return the list of parameters of the quic_transport_parameters extension: the serialization
 * without the length that QuicTransportParameters puts in front.
 */
std::vector<uint8_t>
TransportParameterList(const QuicTransportParameters& tp)
{
    Buffer buffer;
    buffer.AddAtStart(tp.GetSerializedSize());
    tp.Serialize(buffer.Begin());
    std::vector<uint8_t> all(buffer.GetSize());
    buffer.CopyData(all.data(), all.size());
    Buffer::Iterator i = buffer.Begin();
    const uint32_t prefix = QuicVarIntLength(QuicReadVarInt(i));
    return std::vector<uint8_t>(all.begin() + prefix, all.end());
}

/** @return the ALPN extension content for a list of names. */
std::vector<uint8_t>
AlpnData(const std::vector<std::string>& names)
{
    std::vector<uint8_t> list;
    for (const auto& name : names)
    {
        list.push_back(static_cast<uint8_t>(name.size()));
        list.insert(list.end(), name.begin(), name.end());
    }
    std::vector<uint8_t> data;
    Put(data, list.size(), 2);
    data.insert(data.end(), list.begin(), list.end());
    return data;
}

} // namespace

QuicTlsProfile
QuicTlsProfile::Ecdsa()
{
    return QuicTlsProfile();
}

QuicTlsProfile
QuicTlsProfile::Rsa()
{
    QuicTlsProfile p;
    p.name = "rsa";
    p.certificateBytes = 789;
    p.certificateVerifyBody = 264;
    return p;
}

QuicTlsProfile
QuicTlsProfile::PqHybrid()
{
    QuicTlsProfile p;
    p.name = "pq-hybrid";
    p.clientHelloBody += 1184; // the ML-KEM-768 public key next to the X25519 one
    p.serverHelloBody += 1088; // the ML-KEM-768 ciphertext
    return p;
}

bool
QuicTlsProfile::FromName(const std::string& name, QuicTlsProfile& profile)
{
    std::string base = name;
    bool mtls = false;
    const std::string suffix = "+mtls";
    if (base.size() > suffix.size() &&
        base.compare(base.size() - suffix.size(), suffix.size(), suffix) == 0)
    {
        mtls = true;
        base.resize(base.size() - suffix.size());
    }
    if (base == "ecdsa")
    {
        profile = Ecdsa();
    }
    else if (base == "rsa")
    {
        profile = Rsa();
    }
    else if (base == "pq-hybrid")
    {
        profile = PqHybrid();
    }
    else
    {
        return false;
    }
    profile.clientAuth = mtls;
    if (mtls)
    {
        profile.name = name;
    }
    return true;
}

std::vector<uint8_t>
QuicTlsEmulator::ClientHello(const QuicTlsProfile& profile,
                             const QuicTransportParameters& tp,
                             const std::vector<std::string>& alpn,
                             bool resumption)
{
    // the extensions: supported_versions, key_share, ALPN, the transport parameters and a padding
    // extension that brings the rest of the message to the size that was measured
    std::vector<uint8_t> exts;
    PutExtension(exts, 43, {0x03, 0x03, 0x04});
    std::vector<uint8_t> keyShare;
    const uint32_t keyBytes = profile.clientHelloBody > 1000 ? 32 + 1184 : 32;
    Put(keyShare, 2 + 2 + keyBytes, 2);
    Put(keyShare, 0x001d, 2);
    Put(keyShare, keyBytes, 2);
    PutZeros(keyShare, keyBytes);
    PutExtension(exts, 51, keyShare);
    if (resumption)
    {
        PutExtension(exts, 41, std::vector<uint8_t>(80, 0));
    }
    PutExtension(exts, QUIC_TLS_EXT_ALPN, AlpnData(alpn));
    PutExtension(exts, QUIC_TLS_EXT_TRANSPORT_PARAMETERS, TransportParameterList(tp));

    std::vector<uint8_t> body;
    Put(body, 0x0303, 2); // legacy_version
    PutZeros(body, 32);   // random
    body.push_back(0);    // legacy_session_id, empty in QUIC (RFC 9001, Section 8.4)
    Put(body, 6, 2);      // three cipher suites
    Put(body, 0x1302, 2);
    Put(body, 0x1301, 2);
    Put(body, 0x1303, 2);
    body.push_back(1); // one compression method
    body.push_back(0);
    const uint32_t fixed = body.size() + 2 + exts.size(); // with the extensions length field
    // the transport parameters and ALPN are not part of the measured size: leave room for them
    const uint32_t extras = 4 + TransportParameterList(tp).size() + 4 + AlpnData(alpn).size();
    const uint32_t measured = profile.clientHelloBody + extras;
    const uint32_t fill = measured > fixed + 4 ? measured - fixed - 4 : 0;
    PutExtension(exts, 21, std::vector<uint8_t>(fill, 0));
    Put(body, exts.size(), 2);
    body.insert(body.end(), exts.begin(), exts.end());

    std::vector<uint8_t> out;
    PutMessage(out, TLS_CLIENT_HELLO, body);
    return out;
}

std::vector<uint8_t>
QuicTlsEmulator::ServerHello(const QuicTlsProfile& profile)
{
    std::vector<uint8_t> exts;
    PutExtension(exts, 43, {0x03, 0x04});
    const uint32_t keyBytes = profile.serverHelloBody > 1000 ? 32 + 1088 : 32;
    std::vector<uint8_t> keyShare;
    Put(keyShare, 0x001d, 2);
    Put(keyShare, keyBytes, 2);
    PutZeros(keyShare, keyBytes);
    PutExtension(exts, 51, keyShare);
    std::vector<uint8_t> body;
    Put(body, 0x0303, 2);
    PutZeros(body, 32);
    body.push_back(0); // the session id of the ClientHello, empty
    Put(body, 0x1302, 2);
    body.push_back(0);
    // the measured hello is a few bytes longer than the two extensions above: an extension
    // that brings it to the measured size
    const uint32_t have = body.size() + 2 + exts.size();
    if (profile.serverHelloBody >= have + 4)
    {
        PutExtension(exts, 21, std::vector<uint8_t>(profile.serverHelloBody - have - 4, 0));
    }
    Put(body, exts.size(), 2);
    body.insert(body.end(), exts.begin(), exts.end());
    std::vector<uint8_t> out;
    PutMessage(out, TLS_SERVER_HELLO, body);
    return out;
}

std::vector<uint8_t>
QuicTlsEmulator::ServerFlight(const QuicTlsProfile& profile,
                              const QuicTransportParameters& tp,
                              const std::string& alpn)
{
    std::vector<uint8_t> out;

    std::vector<uint8_t> exts;
    PutExtension(exts, QUIC_TLS_EXT_ALPN, AlpnData({alpn}));
    PutExtension(exts, QUIC_TLS_EXT_TRANSPORT_PARAMETERS, TransportParameterList(tp));
    std::vector<uint8_t> ee;
    Put(ee, exts.size(), 2);
    ee.insert(ee.end(), exts.begin(), exts.end());
    PutMessage(out, TLS_ENCRYPTED_EXTENSIONS, ee);

    if (profile.clientAuth)
    {
        std::vector<uint8_t> request;
        request.push_back(0); // certificate_request_context
        std::vector<uint8_t> reqExts;
        PutExtension(reqExts, 13, std::vector<uint8_t>(18, 0)); // signature_algorithms
        PutExtension(reqExts, 47, std::vector<uint8_t>(20, 0)); // certificate_authorities
        Put(request, reqExts.size(), 2);
        request.insert(request.end(), reqExts.begin(), reqExts.end());
        PutMessage(out, TLS_CERTIFICATE_REQUEST, request);
    }

    std::vector<uint8_t> certificate;
    certificate.push_back(0); // certificate_request_context
    const uint32_t entryBytes = 3 + profile.certificateBytes + 2;
    Put(certificate, entryBytes * profile.chainLength, 3);
    for (uint32_t k = 0; k < profile.chainLength; ++k)
    {
        Put(certificate, profile.certificateBytes, 3);
        PutZeros(certificate, profile.certificateBytes);
        Put(certificate, 0, 2); // no extensions
    }
    PutMessage(out, TLS_CERTIFICATE, certificate);

    std::vector<uint8_t> verify;
    Put(verify, profile.name.rfind("rsa", 0) == 0 ? 0x0804 : 0x0403, 2);
    const uint32_t signature =
        profile.certificateVerifyBody > 4 ? profile.certificateVerifyBody - 4 : 0;
    Put(verify, signature, 2);
    PutZeros(verify, signature);
    PutMessage(out, TLS_CERTIFICATE_VERIFY, verify);

    PutMessage(out, TLS_FINISHED, std::vector<uint8_t>(profile.finishedBody, 0));
    return out;
}

std::vector<uint8_t>
QuicTlsEmulator::ClientFlight(const QuicTlsProfile& profile)
{
    std::vector<uint8_t> out;
    if (profile.clientAuth)
    {
        std::vector<uint8_t> certificate;
        certificate.push_back(0);
        Put(certificate, 3 + profile.certificateBytes + 2, 3);
        Put(certificate, profile.certificateBytes, 3);
        PutZeros(certificate, profile.certificateBytes);
        Put(certificate, 0, 2);
        PutMessage(out, TLS_CERTIFICATE, certificate);

        std::vector<uint8_t> verify;
        Put(verify, profile.name.rfind("rsa", 0) == 0 ? 0x0804 : 0x0403, 2);
        const uint32_t signature =
            profile.certificateVerifyBody > 4 ? profile.certificateVerifyBody - 4 : 0;
        Put(verify, signature, 2);
        PutZeros(verify, signature);
        PutMessage(out, TLS_CERTIFICATE_VERIFY, verify);
    }
    PutMessage(out, TLS_FINISHED, std::vector<uint8_t>(profile.finishedBody, 0));
    return out;
}

std::vector<uint8_t>
QuicTlsEmulator::NewSessionTicket(const QuicTlsProfile& profile)
{
    std::vector<uint8_t> out;
    PutMessage(out, TLS_NEW_SESSION_TICKET, std::vector<uint8_t>(profile.ticketBody, 0));
    return out;
}

void
QuicTlsParser::Append(const std::vector<uint8_t>& data)
{
    m_buffer.insert(m_buffer.end(), data.begin(), data.end());
}

bool
QuicTlsParser::Next(uint8_t& type, std::vector<uint8_t>& body)
{
    if (m_buffer.size() < 4)
    {
        return false;
    }
    const uint32_t length = (m_buffer[1] << 16) | (m_buffer[2] << 8) | m_buffer[3];
    if (m_buffer.size() < 4 + length)
    {
        return false;
    }
    type = m_buffer[0];
    body.assign(m_buffer.begin() + 4, m_buffer.begin() + 4 + length);
    m_buffer.erase(m_buffer.begin(), m_buffer.begin() + 4 + length);
    return true;
}

bool
QuicTlsParser::FindExtension(uint8_t type,
                             const std::vector<uint8_t>& body,
                             uint16_t extension,
                             std::vector<uint8_t>& data)
{
    size_t at = 0;
    auto need = [&](size_t n) { return at + n <= body.size(); };
    auto get = [&](size_t n) {
        uint32_t v = 0;
        for (size_t k = 0; k < n; ++k)
        {
            v = (v << 8) | body[at++];
        }
        return v;
    };
    if (type == TLS_CLIENT_HELLO)
    {
        if (!need(2 + 32 + 1))
        {
            return false;
        }
        at += 2 + 32;
        const uint32_t session = get(1);
        if (!need(session + 2))
        {
            return false;
        }
        at += session;
        const uint32_t suites = get(2);
        if (!need(suites + 1))
        {
            return false;
        }
        at += suites;
        const uint32_t compression = get(1);
        if (!need(compression))
        {
            return false;
        }
        at += compression;
    }
    else if (type == TLS_SERVER_HELLO)
    {
        if (!need(2 + 32 + 1))
        {
            return false;
        }
        at += 2 + 32;
        const uint32_t session = get(1);
        if (!need(session + 3))
        {
            return false;
        }
        at += session + 3;
    }
    if (!need(2))
    {
        return false;
    }
    const uint32_t total = get(2);
    if (!need(total) || at + total != body.size())
    {
        return false;
    }
    const size_t end = at + total;
    bool found = false;
    while (at < end)
    {
        if (end - at < 4)
        {
            return false;
        }
        const uint32_t kind = get(2);
        const uint32_t length = get(2);
        if (end - at < length)
        {
            return false;
        }
        if (kind == extension && !found)
        {
            data.assign(body.begin() + at, body.begin() + at + length);
            found = true;
        }
        at += length;
    }
    return found;
}

bool
QuicTlsParser::ParseAlpn(const std::vector<uint8_t>& data, std::vector<std::string>& names)
{
    if (data.size() < 2)
    {
        return false;
    }
    const size_t total = (data[0] << 8) | data[1];
    if (total + 2 != data.size())
    {
        return false;
    }
    names.clear();
    size_t at = 2;
    while (at < data.size())
    {
        const size_t length = data[at++];
        if (length == 0 || at + length > data.size())
        {
            return false;
        }
        names.emplace_back(data.begin() + at, data.begin() + at + length);
        at += length;
    }
    return !names.empty();
}

bool
QuicTlsParser::ParseTransportParameters(const std::vector<uint8_t>& data,
                                        QuicTransportParameters& tp)
{
    // the serialization of the parameters starts with the number of bytes that follow
    Buffer buffer;
    buffer.AddAtStart(QuicVarIntLength(data.size()) + data.size());
    Buffer::Iterator i = buffer.Begin();
    QuicWriteVarInt(i, data.size());
    for (uint8_t byte : data)
    {
        i.WriteU8(byte);
    }
    QuicTransportParameters parsed;
    parsed.Deserialize(buffer.Begin());
    if (!parsed.IsValid())
    {
        return false;
    }
    tp = parsed;
    return true;
}

} // namespace ns3
