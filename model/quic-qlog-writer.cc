/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#include "quic-qlog-writer.h"

#include "quic-subheader.h"
#include "quic-wire.h"

#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicQlogWriter");

NS_OBJECT_ENSURE_REGISTERED(QuicQlogWriter);

namespace
{

/** Identifier of the event schema of the QUIC events, the draft the writer follows. */
const char* const QLOG_QUIC_SCHEMA = "urn:ietf:params:qlog:events:quic-14";

/** How many sent packet types are remembered, to say the type of a packet when it is lost. */
constexpr size_t SENT_TYPES_KEPT = 8192;

/**
 * @param code a transport error code.
 * @return the name the qlog draft gives to the code.
 */
std::string
TransportErrorName(uint64_t code)
{
    static const char* const names[] = {"no_error",
                                        "internal_error",
                                        "connection_refused",
                                        "flow_control_error",
                                        "stream_limit_error",
                                        "stream_state_error",
                                        "final_size_error",
                                        "frame_encoding_error",
                                        "transport_parameter_error",
                                        "connection_id_limit_error",
                                        "protocol_violation",
                                        "invalid_token",
                                        "application_error",
                                        "crypto_buffer_exceeded",
                                        "key_update_error",
                                        "aead_limit_reached",
                                        "no_viable_path"};
    if (code < sizeof(names) / sizeof(names[0]))
    {
        return names[code];
    }
    if (code >= 0x100 && code <= 0x1ff)
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "crypto_error_0x%03x", static_cast<unsigned>(code));
        return buf;
    }
    return "unknown";
}

/**
 * @param h a header.
 * @return the packet type in the words of the qlog draft.
 */
std::string
PacketTypeName(const QuicHeader& h)
{
    if (h.IsShort())
    {
        return "1RTT";
    }
    if (h.IsVersionNegotiation())
    {
        return "version_negotiation";
    }
    if (h.IsInitial())
    {
        return "initial";
    }
    if (h.IsRetry())
    {
        return "retry";
    }
    if (h.IsHandshake())
    {
        return "handshake";
    }
    if (h.IsORTT())
    {
        return "0RTT";
    }
    return "unknown";
}

/**
 * @param version a version number.
 * @return the version as eight hexadecimal digits.
 */
std::string
VersionHex(uint32_t version)
{
    uint8_t bytes[4] = {static_cast<uint8_t>(version >> 24),
                        static_cast<uint8_t>(version >> 16),
                        static_cast<uint8_t>(version >> 8),
                        static_cast<uint8_t>(version)};
    return QuicQlogWriter::Hex(bytes, 4);
}

/**
 * @param cid a connection id.
 * @return the id as a quoted hexadecimal string.
 */
std::string
CidJson(const QuicConnectionId& cid)
{
    return "\"" + QuicQlogWriter::Hex(cid.GetBytes(), cid.GetLength()) + "\"";
}

/**
 * @param address an address and a port.
 * @return the member of a TupleEndpointInfo that describes it, or an empty string.
 */
std::string
EndpointJson(const Address& address)
{
    std::ostringstream os;
    if (InetSocketAddress::IsMatchingType(address))
    {
        InetSocketAddress a = InetSocketAddress::ConvertFrom(address);
        os << "\"address_v4\":{\"ip\":\"" << a.GetIpv4() << "\",\"port\":" << a.GetPort() << "}";
    }
    else if (Inet6SocketAddress::IsMatchingType(address))
    {
        Inet6SocketAddress a = Inet6SocketAddress::ConvertFrom(address);
        os << "\"address_v6\":{\"ip\":\"" << a.GetIpv6() << "\",\"port\":" << a.GetPort() << "}";
    }
    return os.str();
}

/**
 * Turn the ACK ranges of an ACK frame into pairs of packet numbers. In memory the ranges are
 * absolute packet numbers: range 0 is (gaps[0], largest], range k is (gaps[k], blocks[k - 1]] and
 * the last one ends at the first ack block field, the lowest packet number acknowledged (see
 * QuicSubheader::AckWireRanges).
 *
 * @param sub the frame.
 * @return the JSON array of [smallest, largest] pairs, the range of the largest number first.
 */
std::string
AckRangesJson(const QuicSubheader& sub)
{
    std::ostringstream os;
    os << "[";
    const std::vector<uint64_t>& gaps = sub.GetGaps();
    const std::vector<uint64_t>& blocks = sub.GetAdditionalAckBlocks();
    const uint64_t count =
        std::min<uint64_t>(sub.GetAckBlockCount(), std::min(gaps.size(), blocks.size()));
    uint64_t high = sub.GetLargestAcknowledged();
    for (uint64_t k = 0; k <= count; ++k)
    {
        const uint64_t low = k < count ? gaps[k] + 1 : sub.GetFirstAckBlock();
        os << (k ? "," : "") << "[" << low << "," << high << "]";
        if (k < count)
        {
            high = blocks[k];
        }
    }
    os << "]";
    return os.str();
}

/**
 * @param sub a frame that carries an error code.
 * @param application true when the code belongs to the application protocol.
 * @return the members "error" and "error_code" in the form the draft asks for.
 */
std::string
ErrorMembers(uint64_t code, bool application)
{
    std::ostringstream os;
    if (application)
    {
        os << "\"error\":\"unknown\",\"error_code\":" << code;
    }
    else
    {
        const std::string name = TransportErrorName(code);
        os << "\"error\":\"" << name << "\"";
        if (name == "unknown")
        {
            os << ",\"error_code\":" << code;
        }
    }
    return os.str();
}

} // namespace

TypeId
QuicQlogWriter::GetTypeId()
{
    static TypeId tid = TypeId("ns3::QuicQlogWriter")
                            .SetParent<Object>()
                            .SetGroupName("Quic")
                            .AddConstructor<QuicQlogWriter>();
    return tid;
}

QuicQlogWriter::QuicQlogWriter()
{
    NS_LOG_FUNCTION(this);
}

QuicQlogWriter::~QuicQlogWriter()
{
    NS_LOG_FUNCTION(this);
    Close();
}

void
QuicQlogWriter::Configure(const std::string& directory, const std::string& vantage, uint32_t nodeId)
{
    m_directory = directory;
    m_vantage = vantage;
    m_nodeId = nodeId;
}

void
QuicQlogWriter::SetGroupId(const QuicConnectionId& odcid)
{
    if (!m_hasGroupId)
    {
        m_groupId = odcid;
        m_hasGroupId = true;
    }
}

bool
QuicQlogWriter::HasGroupId() const
{
    return m_hasGroupId;
}

std::string
QuicQlogWriter::GetFileName() const
{
    return m_fileName;
}

void
QuicQlogWriter::Close()
{
    if (m_out.is_open())
    {
        m_out.flush();
        m_out.close();
    }
}

std::string
QuicQlogWriter::Quote(const std::string& text)
{
    std::string out = "\"";
    for (unsigned char c : text)
    {
        switch (c)
        {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20 || c >= 0x7f)
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else
            {
                out += static_cast<char>(c);
            }
        }
    }
    out += "\"";
    return out;
}

std::string
QuicQlogWriter::Hex(const uint8_t* bytes, size_t count)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(count * 2);
    for (size_t k = 0; k < count; ++k)
    {
        out += digits[bytes[k] >> 4];
        out += digits[bytes[k] & 0x0f];
    }
    return out;
}

std::string
QuicQlogWriter::FormatMs(Time t)
{
    int64_t ns = t.GetNanoSeconds();
    std::ostringstream os;
    if (ns < 0)
    {
        os << "-";
        ns = -ns;
    }
    os << (ns / 1000000) << "." << std::setfill('0') << std::setw(6) << (ns % 1000000);
    return os.str();
}

void
QuicQlogWriter::Open()
{
    if (m_out.is_open())
    {
        return;
    }
    std::string dir = m_directory.empty() ? "." : m_directory;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (m_fileName.empty())
    {
        std::ostringstream name;
        name << dir << "/node" << m_nodeId << "-" << m_vantage << "-"
             << Hex(m_groupId.GetBytes(), m_groupId.GetLength()) << ".sqlog";
        m_fileName = name.str();
    }
    m_out.open(m_fileName, m_headerWritten ? std::ios::app : std::ios::trunc);
    if (!m_out.is_open())
    {
        NS_LOG_WARN("Cannot open the qlog file " << m_fileName);
        return;
    }
    if (!m_headerWritten)
    {
        std::ostringstream h;
        h << "{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\","
          << "\"serialization_format\":\"application/qlog+json-seq\","
          << "\"title\":\"ns-3 QUIC connection\","
          << "\"description\":\"Events of one QUIC connection in the ns-3 simulator\","
          << "\"trace\":{\"common_fields\":{\"group_id\":\""
          << Hex(m_groupId.GetBytes(), m_groupId.GetLength()) << "\","
          << "\"time_format\":\"relative_to_epoch\","
          << "\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}},"
          << "\"vantage_point\":{\"name\":\"node " << m_nodeId << "\",\"type\":\"" << m_vantage
          << "\"},\"event_schemas\":[\"" << QLOG_QUIC_SCHEMA << "\"]}}";
        m_out << '\x1e' << h.str() << '\n';
        m_headerWritten = true;
        // a program that does not destroy the sockets still gets a complete file
        Simulator::ScheduleDestroy(&QuicQlogWriter::Close, Ptr<QuicQlogWriter>(this));
    }
}

void
QuicQlogWriter::Event(const std::string& name, const std::string& data)
{
    Open();
    if (!m_out.is_open())
    {
        return;
    }
    m_out << '\x1e' << "{\"time\":" << FormatMs(Simulator::Now()) << ",\"name\":\"quic:" << name
          << "\",\"data\":" << data << "}\n";
}

void
QuicQlogWriter::ConnectionStarted(const Address& local,
                                  const Address& remote,
                                  const QuicConnectionId& localCid)
{
    std::ostringstream os;
    std::string l = EndpointJson(local);
    std::string r = EndpointJson(remote);
    os << "{";
    bool first = true;
    if (!l.empty())
    {
        os << "\"local\":{" << l;
        if (!localCid.IsEmpty())
        {
            os << ",\"connection_ids\":[" << CidJson(localCid) << "]";
        }
        os << "}";
        first = false;
    }
    if (!r.empty())
    {
        os << (first ? "" : ",") << "\"remote\":{" << r << "}";
    }
    os << "}";
    Event("connection_started", os.str());
}

void
QuicQlogWriter::ConnectionClosed(const std::string& initiator,
                                 const std::string& trigger,
                                 uint64_t errorCode,
                                 bool hasErrorCode,
                                 bool applicationError,
                                 const std::string& reason)
{
    std::ostringstream os;
    os << "{\"initiator\":\"" << initiator << "\"";
    if (hasErrorCode)
    {
        if (applicationError)
        {
            os << ",\"application_error\":\"unknown\",\"error_code\":" << errorCode;
        }
        else
        {
            const std::string name = TransportErrorName(errorCode);
            os << ",\"connection_error\":\"" << name << "\"";
            if (name == "unknown")
            {
                os << ",\"error_code\":" << errorCode;
            }
        }
    }
    if (!reason.empty())
    {
        os << ",\"reason\":" << Quote(reason);
    }
    os << ",\"trigger\":\"" << trigger << "\"}";
    Event("connection_closed", os.str());
}

void
QuicQlogWriter::ParametersSet(const std::string& initiator, const QuicTransportParameters& tp)
{
    std::ostringstream os;
    os << "{\"initiator\":\"" << initiator << "\"";
    if (!tp.GetOriginalDestinationConnectionId().IsEmpty())
    {
        os << ",\"original_destination_connection_id\":"
           << CidJson(tp.GetOriginalDestinationConnectionId());
    }
    if (!tp.GetInitialSourceConnectionId().IsEmpty())
    {
        os << ",\"initial_source_connection_id\":" << CidJson(tp.GetInitialSourceConnectionId());
    }
    if (!tp.GetRetrySourceConnectionId().IsEmpty())
    {
        os << ",\"retry_source_connection_id\":" << CidJson(tp.GetRetrySourceConnectionId());
    }
    if (tp.GetStatelessResetTokenHi() != 0 || tp.GetStatelessResetTokenLo() != 0)
    {
        uint8_t token[16];
        for (int k = 0; k < 8; ++k)
        {
            token[k] = static_cast<uint8_t>(tp.GetStatelessResetTokenHi() >> (56 - 8 * k));
            token[8 + k] = static_cast<uint8_t>(tp.GetStatelessResetTokenLo() >> (56 - 8 * k));
        }
        os << ",\"stateless_reset_token\":\"" << Hex(token, 16) << "\"";
    }
    os << ",\"disable_active_migration\":" << (tp.GetDisableActiveMigration() ? "true" : "false")
       << ",\"max_idle_timeout\":" << tp.GetIdleTimeout()
       << ",\"max_udp_payload_size\":" << tp.GetMaxUdpPayloadSize()
       << ",\"ack_delay_exponent\":" << static_cast<unsigned>(tp.GetAckDelayExponent())
       << ",\"max_ack_delay\":" << tp.GetMaxAckDelay()
       << ",\"active_connection_id_limit\":" << tp.GetActiveConnectionIdLimit()
       << ",\"initial_max_data\":" << tp.GetInitialMaxData()
       << ",\"initial_max_stream_data_bidi_local\":" << tp.GetInitialMaxStreamData()
       << ",\"initial_max_stream_data_bidi_remote\":" << tp.GetInitialMaxStreamDataBidiRemote()
       << ",\"initial_max_stream_data_uni\":" << tp.GetInitialMaxStreamDataUni()
       << ",\"initial_max_streams_bidi\":" << tp.GetInitialMaxStreamIdBidi()
       << ",\"initial_max_streams_uni\":" << tp.GetInitialMaxStreamIdUni();
    const auto& raw = tp.GetRawParameters();
    if (!raw.empty())
    {
        os << ",\"unknown_parameters\":[";
        bool first = true;
        for (const auto& entry : raw)
        {
            os << (first ? "" : ",") << "{\"id\":" << entry.first << ",\"value\":\""
               << Hex(entry.second.data(), entry.second.size()) << "\"}";
            first = false;
        }
        os << "]";
    }
    os << "}";
    Event("parameters_set", os.str());
}

void
QuicQlogWriter::VersionInformation(uint32_t chosen,
                                   const std::vector<uint32_t>& local,
                                   bool isClient)
{
    std::ostringstream os;
    os << "{\"" << (isClient ? "client_versions" : "server_versions") << "\":[";
    for (size_t k = 0; k < local.size(); ++k)
    {
        os << (k ? "," : "") << "\"" << VersionHex(local[k]) << "\"";
    }
    os << "],\"chosen_version\":\"" << VersionHex(chosen) << "\"}";
    Event("version_information", os.str());
}

std::string
QuicQlogWriter::HeaderToJson(const QuicHeader& h)
{
    std::ostringstream os;
    const std::string type = PacketTypeName(h);
    os << "{\"packet_type\":\"" << type << "\"";
    if (h.HasPacketNumber())
    {
        os << ",\"packet_number\":" << h.GetPacketNumber().GetValue()
           << ",\"packet_number_length\":" << static_cast<unsigned>(h.GetPacketNumberLength());
    }
    if (h.IsShort())
    {
        os << ",\"spin_bit\":" << (h.GetSpinBit() ? "true" : "false")
           << ",\"key_phase_bit\":" << (h.GetKeyPhaseBit() ? "true" : "false");
    }
    else
    {
        os << ",\"version\":\"" << VersionHex(h.GetVersion()) << "\"";
        os << ",\"scil\":" << static_cast<unsigned>(h.GetSourceConnectionId().GetLength());
        os << ",\"dcil\":" << static_cast<unsigned>(h.GetDestinationConnectionId().GetLength());
        os << ",\"scid\":" << CidJson(h.GetSourceConnectionId());
    }
    if (!h.GetDestinationConnectionId().IsEmpty())
    {
        os << ",\"dcid\":" << CidJson(h.GetDestinationConnectionId());
    }
    if ((h.IsInitial() || h.IsRetry()) && !h.GetToken().empty())
    {
        os << ",\"token\":{\"type\":\"" << (h.IsRetry() ? "retry" : "resumption")
           << "\",\"raw\":{\"length\":" << h.GetToken().size() << "}}";
    }
    os << "}";
    return os.str();
}

std::string
QuicQlogWriter::FramesToJson(Ptr<const Packet> payload, uint8_t ackDelayExponent)
{
    std::ostringstream os;
    os << "[";
    Ptr<Packet> rest = payload->Copy();
    bool first = true;
    while (rest->GetSize() > 0)
    {
        const uint32_t before = rest->GetSize();
        QuicSubheader sub;
        rest->RemoveHeader(sub);
        const uint32_t headerBytes = before - rest->GetSize();
        std::ostringstream f;
        if (!sub.IsValid())
        {
            f << "{\"frame_type\":\"unknown\",\"frame_type_bytes\":" << sub.GetFrameType() << "}";
            os << (first ? "" : ",") << f.str();
            break;
        }
        const uint64_t dataLen =
            std::min<uint64_t>(sub.GetPayloadLength(rest->GetSize()), rest->GetSize());
        const uint64_t type = sub.GetFrameType();
        auto raw = [&](uint64_t total, uint64_t payloadLength) {
            f << ",\"raw\":{\"length\":" << total << ",\"payload_length\":" << payloadLength << "}";
        };
        if (sub.IsPadding())
        {
            f << "{\"frame_type\":\"padding\"";
            raw(headerBytes, headerBytes);
        }
        else if (sub.IsPing())
        {
            f << "{\"frame_type\":\"ping\"";
        }
        else if (sub.IsAck())
        {
            const uint64_t delayUs = sub.GetAckDelay() << ackDelayExponent;
            f << "{\"frame_type\":\"ack\",\"ack_delay\":"
              << FormatMs(MicroSeconds(static_cast<int64_t>(delayUs)))
              << ",\"acked_ranges\":" << AckRangesJson(sub);
            if (sub.HasEcnCounts())
            {
                f << ",\"ect0\":" << sub.GetEct0Count() << ",\"ect1\":" << sub.GetEct1Count()
                  << ",\"ce\":" << sub.GetEcnCeCount();
            }
        }
        else if (sub.IsRstStream())
        {
            f << "{\"frame_type\":\"reset_stream\",\"stream_id\":" << sub.GetStreamId() << ","
              << ErrorMembers(sub.GetErrorCode(), true) << ",\"final_size\":" << sub.GetOffset();
        }
        else if (sub.IsStopSending())
        {
            f << "{\"frame_type\":\"stop_sending\",\"stream_id\":" << sub.GetStreamId() << ","
              << ErrorMembers(sub.GetErrorCode(), true);
        }
        else if (sub.IsCrypto())
        {
            f << "{\"frame_type\":\"crypto\",\"offset\":" << sub.GetOffset();
            raw(headerBytes + dataLen, dataLen);
        }
        else if (sub.IsNewToken())
        {
            f << "{\"frame_type\":\"new_token\",\"token\":{\"raw\":{\"length\":"
              << sub.GetToken().size() << "}}";
        }
        else if (sub.IsStream())
        {
            f << "{\"frame_type\":\"stream\",\"stream_id\":" << sub.GetStreamId()
              << ",\"offset\":" << sub.GetOffset()
              << ",\"fin\":" << (sub.IsStreamFin() ? "true" : "false");
            raw(headerBytes + dataLen, dataLen);
        }
        else if (sub.IsMaxData())
        {
            f << "{\"frame_type\":\"max_data\",\"maximum\":" << sub.GetMaxData();
        }
        else if (sub.IsMaxStreamData())
        {
            f << "{\"frame_type\":\"max_stream_data\",\"stream_id\":" << sub.GetStreamId()
              << ",\"maximum\":" << sub.GetMaxStreamData();
        }
        else if (type == QuicSubheader::MAX_STREAMS_BIDI || type == QuicSubheader::MAX_STREAMS_UNI)
        {
            f << "{\"frame_type\":\"max_streams\",\"stream_type\":\""
              << (type == QuicSubheader::MAX_STREAMS_BIDI ? "bidirectional" : "unidirectional")
              << "\",\"maximum\":" << sub.GetMaxStreamId();
        }
        else if (sub.IsBlocked())
        {
            f << "{\"frame_type\":\"data_blocked\",\"limit\":" << sub.GetOffset();
        }
        else if (sub.IsStreamBlocked())
        {
            f << "{\"frame_type\":\"stream_data_blocked\",\"stream_id\":" << sub.GetStreamId()
              << ",\"limit\":" << sub.GetOffset();
        }
        else if (type == QuicSubheader::STREAMS_BLOCKED_BIDI ||
                 type == QuicSubheader::STREAMS_BLOCKED_UNI)
        {
            f << "{\"frame_type\":\"streams_blocked\",\"stream_type\":\""
              << (type == QuicSubheader::STREAMS_BLOCKED_BIDI ? "bidirectional" : "unidirectional")
              << "\",\"limit\":" << sub.GetStreamId();
        }
        else if (sub.IsNewConnectionId())
        {
            uint8_t token[16];
            for (int k = 0; k < 8; ++k)
            {
                token[k] = static_cast<uint8_t>(sub.GetResetTokenHi() >> (56 - 8 * k));
                token[8 + k] = static_cast<uint8_t>(sub.GetResetTokenLo() >> (56 - 8 * k));
            }
            f << "{\"frame_type\":\"new_connection_id\",\"sequence_number\":" << sub.GetSequence()
              << ",\"retire_prior_to\":" << sub.GetRetirePriorTo() << ",\"connection_id_length\":"
              << static_cast<unsigned>(sub.GetConnectionId().GetLength())
              << ",\"connection_id\":" << CidJson(sub.GetConnectionId())
              << ",\"stateless_reset_token\":\"" << Hex(token, 16) << "\"";
        }
        else if (type == QuicSubheader::RETIRE_CONNECTION_ID)
        {
            f << "{\"frame_type\":\"retire_connection_id\",\"sequence_number\":"
              << sub.GetSequence();
        }
        else if (sub.IsPathChallenge() || sub.IsPathResponse())
        {
            uint8_t data[8];
            for (int k = 0; k < 8; ++k)
            {
                data[k] = static_cast<uint8_t>(sub.GetData() >> (56 - 8 * k));
            }
            f << "{\"frame_type\":\""
              << (sub.IsPathChallenge() ? "path_challenge" : "path_response") << "\",\"data\":\""
              << Hex(data, 8) << "\"";
        }
        else if (sub.IsConnectionClose() || sub.IsApplicationClose())
        {
            const bool app = sub.IsApplicationClose();
            std::vector<uint8_t> phrase = sub.GetReasonPhrase();
            f << "{\"frame_type\":\"connection_close\",\"error_space\":\""
              << (app ? "application" : "transport") << "\","
              << ErrorMembers(sub.GetErrorCode(), app);
            if (!app)
            {
                f << ",\"trigger_frame_type\":" << sub.GetTriggerFrameType();
            }
            if (!phrase.empty())
            {
                f << ",\"reason\":" << Quote(std::string(phrase.begin(), phrase.end()));
            }
        }
        else if (type == QuicSubheader::HANDSHAKE_DONE)
        {
            f << "{\"frame_type\":\"handshake_done\"";
        }
        else if (sub.IsDatagram())
        {
            f << "{\"frame_type\":\"datagram\"";
            raw(headerBytes + dataLen, dataLen);
        }
        else
        {
            f << "{\"frame_type\":\"unknown\",\"frame_type_bytes\":" << type;
        }
        f << "}";
        os << (first ? "" : ",") << f.str();
        first = false;
        if (dataLen > 0)
        {
            rest->RemoveAtStart(static_cast<uint32_t>(dataLen));
        }
    }
    os << "]";
    return os.str();
}

std::string
QuicQlogWriter::PacketMembers(const QuicHeader& header, uint32_t payloadSize)
{
    const uint32_t tag = header.HasAeadTag() ? QUIC_AEAD_TAG_SIZE : 0;
    std::ostringstream os;
    os << "\"header\":" << HeaderToJson(header)
       << ",\"raw\":{\"length\":" << (header.GetSerializedSize() + payloadSize + tag)
       << ",\"payload_length\":" << (payloadSize + tag) << "}";
    return os.str();
}

void
QuicQlogWriter::PacketSent(const QuicHeader& header,
                           Ptr<const Packet> payload,
                           uint8_t ackDelayExponent,
                           bool mtuProbe)
{
    if (header.HasPacketNumber())
    {
        m_sentTypes[header.GetPacketNumber().GetValue()] = PacketTypeName(header);
        if (m_sentTypes.size() > SENT_TYPES_KEPT)
        {
            m_sentTypes.erase(m_sentTypes.begin());
        }
    }
    std::ostringstream os;
    os << "{" << PacketMembers(header, payload->GetSize())
       << ",\"frames\":" << FramesToJson(payload, ackDelayExponent);
    if (mtuProbe)
    {
        os << ",\"is_mtu_probe_packet\":true";
    }
    os << "}";
    Event("packet_sent", os.str());
}

void
QuicQlogWriter::PacketReceived(const QuicHeader& header,
                               Ptr<const Packet> payload,
                               uint8_t ackDelayExponent)
{
    std::ostringstream os;
    os << "{" << PacketMembers(header, payload->GetSize())
       << ",\"frames\":" << FramesToJson(payload, ackDelayExponent) << "}";
    Event("packet_received", os.str());
}

void
QuicQlogWriter::PacketDropped(const QuicHeader* header,
                              uint32_t size,
                              const std::string& trigger,
                              const std::string& detail)
{
    std::ostringstream os;
    os << "{";
    if (header != nullptr)
    {
        os << "\"header\":" << HeaderToJson(*header) << ",";
    }
    os << "\"raw\":{\"length\":" << size << "}";
    if (!detail.empty())
    {
        os << ",\"details\":{\"reason\":" << Quote(detail) << "}";
    }
    os << ",\"trigger\":\"" << trigger << "\"}";
    Event("packet_dropped", os.str());
}

void
QuicQlogWriter::PacketLost(uint64_t packetNumber, const std::string& trigger)
{
    auto it = m_sentTypes.find(packetNumber);
    std::ostringstream os;
    os << "{\"header\":{\"packet_type\":\"" << (it != m_sentTypes.end() ? it->second : "1RTT")
       << "\",\"packet_number\":" << packetNumber << "},\"trigger\":\"" << trigger << "\"}";
    Event("packet_lost", os.str());
}

void
QuicQlogWriter::UdpDatagram(bool sent, uint32_t size)
{
    std::ostringstream os;
    os << "{\"count\":1,\"raw\":[{\"length\":" << size << "}]}";
    Event(sent ? "udp_datagrams_sent" : "udp_datagrams_received", os.str());
}

void
QuicQlogWriter::RecoveryMetrics(Time minRtt,
                                Time smoothedRtt,
                                Time latestRtt,
                                Time rttVar,
                                uint32_t ptoCount,
                                uint32_t cwnd,
                                uint32_t bytesInFlight,
                                uint32_t ssthresh)
{
    const bool haveMin = minRtt != Time::Max() && minRtt.IsPositive();
    const int64_t minNs = haveMin ? minRtt.GetNanoSeconds() : 0;
    std::ostringstream os;
    os << "{";
    bool first = true;
    auto put = [&](const char* name, const std::string& value) {
        os << (first ? "" : ",") << "\"" << name << "\":" << value;
        first = false;
    };
    const bool all = !m_metricsValid;
    if (haveMin && (all || minNs != m_lastMinRtt))
    {
        put("min_rtt", FormatMs(minRtt));
    }
    if (smoothedRtt.IsPositive() && (all || smoothedRtt.GetNanoSeconds() != m_lastSrtt))
    {
        put("smoothed_rtt", FormatMs(smoothedRtt));
    }
    if (latestRtt.IsPositive() && (all || latestRtt.GetNanoSeconds() != m_lastLatestRtt))
    {
        put("latest_rtt", FormatMs(latestRtt));
    }
    if (rttVar.IsPositive() && (all || rttVar.GetNanoSeconds() != m_lastRttVar))
    {
        put("rtt_variance", FormatMs(rttVar));
    }
    if (all || ptoCount != m_lastPto)
    {
        put("pto_count", std::to_string(ptoCount));
    }
    if (all || cwnd != m_lastCwnd)
    {
        put("congestion_window", std::to_string(cwnd));
    }
    if (all || bytesInFlight != m_lastInFlight)
    {
        put("bytes_in_flight", std::to_string(bytesInFlight));
    }
    if (ssthresh != UINT32_MAX && (all || ssthresh != m_lastSsthresh))
    {
        put("ssthresh", std::to_string(ssthresh));
    }
    os << "}";
    m_metricsValid = true;
    m_lastMinRtt = minNs;
    m_lastSrtt = smoothedRtt.GetNanoSeconds();
    m_lastLatestRtt = latestRtt.GetNanoSeconds();
    m_lastRttVar = rttVar.GetNanoSeconds();
    m_lastPto = ptoCount;
    m_lastCwnd = cwnd;
    m_lastInFlight = bytesInFlight;
    m_lastSsthresh = ssthresh;
    if (!first)
    {
        Event("recovery_metrics_updated", os.str());
    }
}

void
QuicQlogWriter::CongestionStateUpdated(const std::string& oldState,
                                       const std::string& newState,
                                       const std::string& trigger)
{
    std::ostringstream os;
    os << "{\"old\":\"" << oldState << "\",\"new\":\"" << newState << "\"";
    if (!trigger.empty())
    {
        os << ",\"trigger\":\"" << trigger << "\"";
    }
    os << "}";
    Event("congestion_state_updated", os.str());
}

void
QuicQlogWriter::TimerUpdated(const std::string& timerType, const std::string& event, Time delta)
{
    std::ostringstream os;
    os << "{\"timer_type\":\"" << timerType << "\",\"event_type\":\"" << event << "\"";
    if (event == "set")
    {
        os << ",\"delta\":" << FormatMs(delta);
    }
    os << "}";
    Event("timer_updated", os.str());
}

} // namespace ns3
