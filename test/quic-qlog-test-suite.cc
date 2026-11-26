/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - observability suite ("quic-qlog").
 *
 * The qlog writer (draft-ietf-quic-qlog-main-schema-15 and quic-events-14) and the trace sources
 * that feed it: the shape of the records, the description of headers and frames, the events of a
 * connection that loses packets, and the guarantee that logging does not change the simulation.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-header.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-qlog-writer.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-subheader.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <unistd.h>
#include <vector>

using namespace ns3;

namespace
{

/**
 * A directory that is removed when the object goes away.
 */
class TempDir
{
  public:
    TempDir()
    {
        static int counter = 0;
        m_path = std::filesystem::temp_directory_path() /
                 ("ns3-quic-qlog-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(m_path);
    }

    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }

    /** @return the directory. */
    std::string Path() const
    {
        return m_path.string();
    }

    /** @return the names of the files in the directory, sorted. */
    std::vector<std::string> Files() const
    {
        std::vector<std::string> names;
        for (const auto& entry : std::filesystem::directory_iterator(m_path))
        {
            names.push_back(entry.path().string());
        }
        std::sort(names.begin(), names.end());
        return names;
    }

  private:
    std::filesystem::path m_path; //!< the directory
};

/**
 * @param path a file.
 * @return its content.
 */
std::string
ReadFile(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream os;
    os << in.rdbuf();
    return os.str();
}

/**
 * @param text a text.
 * @param needle what to look for.
 * @return how many times the needle occurs.
 */
size_t
Count(const std::string& text, const std::string& needle)
{
    size_t n = 0;
    for (size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1))
    {
        ++n;
    }
    return n;
}

/**
 * The frames of a packet.
 *
 * @param frames the frames, each with the number of data bytes after it.
 * @return the packet.
 */
Ptr<Packet>
Frames(const std::vector<std::pair<QuicSubheader, uint32_t>>& frames)
{
    Ptr<Packet> packet = Create<Packet>();
    for (auto it = frames.rbegin(); it != frames.rend(); ++it)
    {
        Ptr<Packet> frame = Create<Packet>(it->second);
        frame->AddHeader(it->first);
        frame->AddAtEnd(packet);
        packet = frame;
    }
    return packet;
}

/**
 * Durations, text escapes and hexadecimal strings.
 */
class QlogFormatTest : public TestCase
{
  public:
    QlogFormatTest()
        : TestCase("durations, escapes and hexadecimal strings")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::FormatMs(Seconds(0)), "0.000000", "zero");
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::FormatMs(MicroSeconds(1500)), "1.500000", "1.5 ms");
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::FormatMs(NanoSeconds(1)), "0.000001", "one ns");
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::FormatMs(Seconds(12)), "12000.000000", "12 s");
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::Quote("a\"b\\c\n\x01"),
                              "\"a\\\"b\\\\c\\n\\u0001\"",
                              "escapes");
        const uint8_t bytes[] = {0x00, 0xab, 0x7f, 0xff};
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::Hex(bytes, 4), "00ab7fff", "hex");
        NS_TEST_ASSERT_MSG_EQ(QuicQlogWriter::Hex(bytes, 0), "", "empty");
    }
};

/**
 * The PacketHeader of the draft for the forms of header the module sends.
 */
class QlogHeaderTest : public TestCase
{
  public:
    QlogHeaderTest()
        : TestCase("packet headers in the form of the draft")
    {
    }

  private:
    void DoRun() override
    {
        uint8_t d[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
        uint8_t s[4] = {1, 2, 3, 4};
        QuicHeader initial = QuicHeader::CreateInitial(QuicConnectionId(d, 8),
                                                       QuicConnectionId(s, 4),
                                                       1,
                                                       QuicPacketNumber(2));
        const std::string i = QuicQlogWriter::HeaderToJson(initial);
        NS_TEST_ASSERT_MSG_NE(i.find("\"packet_type\":\"initial\""), std::string::npos, i);
        NS_TEST_ASSERT_MSG_NE(i.find("\"packet_number\":2"), std::string::npos, i);
        NS_TEST_ASSERT_MSG_NE(i.find("\"version\":\"00000001\""), std::string::npos, i);
        NS_TEST_ASSERT_MSG_NE(i.find("\"scil\":4"), std::string::npos, i);
        NS_TEST_ASSERT_MSG_NE(i.find("\"dcil\":8"), std::string::npos, i);
        NS_TEST_ASSERT_MSG_NE(i.find("\"scid\":\"01020304\""), std::string::npos, i);
        NS_TEST_ASSERT_MSG_NE(i.find("\"dcid\":\"8394c8f03e515708\""), std::string::npos, i);
        NS_TEST_ASSERT_MSG_EQ(i.find("\"token\""), std::string::npos, "no token when empty");

        QuicHeader withToken = QuicHeader::CreateInitial(QuicConnectionId(d, 8),
                                                         QuicConnectionId(s, 4),
                                                         1,
                                                         QuicPacketNumber(0),
                                                         {1, 2, 3});
        NS_TEST_ASSERT_MSG_NE(QuicQlogWriter::HeaderToJson(withToken).find("\"length\":3"),
                              std::string::npos,
                              "token length");

        QuicHeader handshake = QuicHeader::CreateHandshake(QuicConnectionId(d, 8),
                                                           QuicConnectionId(s, 4),
                                                           1,
                                                           QuicPacketNumber(7));
        NS_TEST_ASSERT_MSG_NE(
            QuicQlogWriter::HeaderToJson(handshake).find("\"packet_type\":\"handshake\""),
            std::string::npos,
            "handshake");

        QuicHeader shortHeader =
            QuicHeader::CreateShort(QuicConnectionId(d, 8), QuicPacketNumber(300), true, true, 0);
        const std::string sh = QuicQlogWriter::HeaderToJson(shortHeader);
        NS_TEST_ASSERT_MSG_NE(sh.find("\"packet_type\":\"1RTT\""), std::string::npos, sh);
        NS_TEST_ASSERT_MSG_NE(sh.find("\"spin_bit\":true"), std::string::npos, sh);
        NS_TEST_ASSERT_MSG_NE(sh.find("\"key_phase_bit\":true"), std::string::npos, sh);
        NS_TEST_ASSERT_MSG_EQ(sh.find("\"version\""), std::string::npos, "no version in short");

        QuicHeader vn = QuicHeader::CreateVersionNegotiation(QuicConnectionId(d, 8),
                                                             QuicConnectionId(s, 4),
                                                             {1});
        NS_TEST_ASSERT_MSG_NE(
            QuicQlogWriter::HeaderToJson(vn).find("\"packet_type\":\"version_negotiation\""),
            std::string::npos,
            "version negotiation");
    }
};

/**
 * The frames of a packet, one by one, with the fields the draft defines.
 */
class QlogFramesTest : public TestCase
{
  public:
    QlogFramesTest()
        : TestCase("frames in the form of the draft")
    {
    }

  private:
    /**
     * Check that a text holds a part.
     *
     * @param json the text.
     * @param part what it has to hold.
     */
    void Has(const std::string& json, const std::string& part)
    {
        NS_TEST_EXPECT_MSG_NE(json.find(part), std::string::npos, part << " in " << json);
    }

    void DoRun() override
    {
        // the ranges 18 to 20 and 12 to 15: in memory, the packet number below the first range,
        // the top of the next one and the lowest packet number
        std::vector<uint64_t> gaps{17};
        std::vector<uint64_t> blocks{15};
        // the delay is 5 units of 2^3 microseconds
        QuicSubheader ack = QuicSubheader::CreateAck(20, 5, 12, gaps, blocks);
        const std::string a =
            QuicQlogWriter::FramesToJson(Frames({{ack, 0}}), /* ackDelayExponent */ 3);
        Has(a, "\"frame_type\":\"ack\"");
        Has(a, "\"ack_delay\":0.040000");
        Has(a, "\"acked_ranges\":[[18,20],[12,15]]");

        uint8_t cid[4] = {9, 8, 7, 6};
        const std::string all = QuicQlogWriter::FramesToJson(
            Frames({{QuicSubheader::CreatePing(), 0},
                    {QuicSubheader::CreateStreamSubHeader(4, 100, 10, true, true, true), 10},
                    {QuicSubheader::CreateCrypto(0, 12), 12},
                    {QuicSubheader::CreateMaxData(5000), 0},
                    {QuicSubheader::CreateMaxStreamData(4, 6000), 0},
                    {QuicSubheader::CreateRstStream(8, 77, 900), 0},
                    {QuicSubheader::CreateStopSending(8, 5), 0},
                    {QuicSubheader::CreateNewConnectionId(2, 1, QuicConnectionId(cid, 4), 1, 2), 0},
                    {QuicSubheader::CreateRetireConnectionId(1), 0},
                    {QuicSubheader::CreateConnectionClose(0x0a, "bad frame"), 0},
                    {QuicSubheader::CreateHandshakeDone(), 0},
                    {QuicSubheader::CreatePadding(), 7}}),
            3);
        Has(all, "{\"frame_type\":\"ping\"}");
        Has(all,
            "{\"frame_type\":\"stream\",\"stream_id\":4,\"offset\":100,\"fin\":true,"
            "\"raw\":{\"length\":");
        Has(all, "\"payload_length\":10}");
        Has(all, "\"frame_type\":\"crypto\",\"offset\":0");
        Has(all, "{\"frame_type\":\"max_data\",\"maximum\":5000}");
        Has(all, "{\"frame_type\":\"max_stream_data\",\"stream_id\":4,\"maximum\":6000}");
        Has(all, "\"frame_type\":\"reset_stream\",\"stream_id\":8,");
        Has(all, "\"error_code\":77,\"final_size\":900}");
        Has(all, "\"frame_type\":\"stop_sending\",\"stream_id\":8,");
        Has(all,
            "\"frame_type\":\"new_connection_id\",\"sequence_number\":2,\"retire_prior_to\":1");
        Has(all, "\"connection_id\":\"09080706\"");
        Has(all, "{\"frame_type\":\"retire_connection_id\",\"sequence_number\":1}");
        Has(all, "\"frame_type\":\"connection_close\",\"error_space\":\"transport\"");
        Has(all, "\"error\":\"protocol_violation\"");
        Has(all, "\"reason\":\"bad frame\"");
        Has(all, "{\"frame_type\":\"handshake_done\"}");
        // PADDING bytes are one frame, with their number as the payload length
        Has(all, "{\"frame_type\":\"padding\",\"raw\":{\"length\":8,\"payload_length\":8}}");
        NS_TEST_ASSERT_MSG_EQ(Count(all, "\"frame_type\""), 12, "twelve frames");

        // a packet that ends in the middle of a frame is cut where the frame is invalid
        Ptr<Packet> cut = Create<Packet>();
        cut->AddHeader(QuicSubheader::CreateMaxData(5000));
        cut->RemoveAtEnd(1);
        Has(QuicQlogWriter::FramesToJson(cut, 3), "\"frame_type\":\"unknown\"");
    }
};

/**
 * The records of a file: the header, the framing with RS and LF, the events written.
 */
class QlogRecordTest : public TestCase
{
  public:
    QlogRecordTest()
        : TestCase("records of a qlog file")
    {
    }

  private:
    void DoRun() override
    {
        TempDir dir;
        {
            Ptr<QuicQlogWriter> w = CreateObject<QuicQlogWriter>();
            w->Configure(dir.Path(), "client", 3);
            uint8_t odcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
            w->SetGroupId(QuicConnectionId(odcid, 8));
            NS_TEST_ASSERT_MSG_EQ(w->GetFileName(), "", "nothing is created before an event");
            w->RecoveryMetrics(MilliSeconds(20),
                               MilliSeconds(22),
                               MilliSeconds(21),
                               MilliSeconds(3),
                               0,
                               14000,
                               0,
                               UINT32_MAX);
            // the same values: no event
            w->RecoveryMetrics(MilliSeconds(20),
                               MilliSeconds(22),
                               MilliSeconds(21),
                               MilliSeconds(3),
                               0,
                               14000,
                               0,
                               UINT32_MAX);
            // only the window and the bytes in flight changed
            w->RecoveryMetrics(MilliSeconds(20),
                               MilliSeconds(22),
                               MilliSeconds(21),
                               MilliSeconds(3),
                               0,
                               15000,
                               1200,
                               UINT32_MAX);
            w->PacketLost(5, "time_threshold");
            w->UdpDatagram(true, 1200);
            w->CongestionStateUpdated("slow_start", "recovery", "packet_lost");
            w->TimerUpdated("pto", "set", MilliSeconds(75));
            w->TimerUpdated("pto", "expired", Seconds(0));
            w->ConnectionClosed("local", "error", 0x0a, true, false, "bad \"frame\"");
            w->Close();
            NS_TEST_ASSERT_MSG_NE(w->GetFileName().find("node3-client-0102030405060708.sqlog"),
                                  std::string::npos,
                                  w->GetFileName());
        }
        auto files = dir.Files();
        NS_TEST_ASSERT_MSG_EQ(files.size(), 1, "one file");
        const std::string text = ReadFile(files[0]);

        // every record: RS, a JSON text on one line, LF
        std::vector<std::string> records;
        size_t at = 0;
        while (at < text.size())
        {
            NS_TEST_ASSERT_MSG_EQ(text[at], '\x1e', "a record starts with RS");
            const size_t end = text.find('\n', at);
            NS_TEST_ASSERT_MSG_NE(end, std::string::npos, "a record ends with LF");
            records.push_back(text.substr(at + 1, end - at - 1));
            at = end + 1;
        }
        NS_TEST_ASSERT_MSG_EQ(records.size(), 9, "header and eight events");
        const std::string& header = records[0];
        NS_TEST_EXPECT_MSG_NE(
            header.find("\"file_schema\":\"urn:ietf:params:qlog:file:sequential\""),
            std::string::npos,
            header);
        NS_TEST_EXPECT_MSG_NE(header.find("\"serialization_format\":\"application/qlog+json-seq\""),
                              std::string::npos,
                              header);
        NS_TEST_EXPECT_MSG_NE(header.find("\"group_id\":\"0102030405060708\""),
                              std::string::npos,
                              header);
        NS_TEST_EXPECT_MSG_NE(header.find("\"type\":\"client\""), std::string::npos, header);
        NS_TEST_EXPECT_MSG_NE(
            header.find("\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-14"),
            std::string::npos,
            header);

        // the first metrics event has all the values, the third only the two that changed
        NS_TEST_EXPECT_MSG_NE(records[1].find("\"name\":\"quic:recovery_metrics_updated\""),
                              std::string::npos,
                              records[1]);
        NS_TEST_EXPECT_MSG_NE(records[1].find("\"min_rtt\":20.000000"), std::string::npos, "min");
        NS_TEST_EXPECT_MSG_NE(records[1].find("\"smoothed_rtt\":22.000000"),
                              std::string::npos,
                              "srtt");
        NS_TEST_EXPECT_MSG_NE(records[1].find("\"congestion_window\":14000"),
                              std::string::npos,
                              "cwnd");
        NS_TEST_EXPECT_MSG_EQ(records[1].find("ssthresh"), std::string::npos, "no ssthresh yet");
        NS_TEST_EXPECT_MSG_NE(
            records[2].find("\"congestion_window\":15000,\"bytes_in_flight\":1200"),
            std::string::npos,
            records[2]);
        NS_TEST_EXPECT_MSG_EQ(records[2].find("min_rtt"), std::string::npos, "unchanged values");
        NS_TEST_EXPECT_MSG_NE(records[3].find("\"name\":\"quic:packet_lost\""),
                              std::string::npos,
                              records[3]);
        NS_TEST_EXPECT_MSG_NE(records[3].find("\"trigger\":\"time_threshold\""),
                              std::string::npos,
                              records[3]);
        NS_TEST_EXPECT_MSG_NE(records[4].find("\"name\":\"quic:udp_datagrams_sent\""),
                              std::string::npos,
                              records[4]);
        NS_TEST_EXPECT_MSG_NE(records[6].find("\"event_type\":\"set\",\"delta\":75.000000"),
                              std::string::npos,
                              records[6]);
        NS_TEST_EXPECT_MSG_EQ(records[7].find("delta"), std::string::npos, "no delta on expiry");
        NS_TEST_EXPECT_MSG_NE(records[8].find("\"connection_error\":\"protocol_violation\""),
                              std::string::npos,
                              records[8]);
        NS_TEST_EXPECT_MSG_NE(records[8].find("\"reason\":\"bad \\\"frame\\\"\""),
                              std::string::npos,
                              records[8]);
    }
};

/**
 * Two nodes with a connection in which both ends send data over a link that loses packets.
 */
class QlogRig
{
  public:
    uint64_t clientTx{0};       //!< Tx trace calls of the client
    uint64_t clientRx{0};       //!< Rx trace calls of the client
    uint64_t serverTx{0};       //!< Tx trace calls of the server
    uint64_t serverRx{0};       //!< Rx trace calls of the server
    uint64_t clientLost{0};     //!< PacketLost trace calls of the client
    uint64_t clientAcked{0};    //!< PacketAcked trace calls of the client
    uint64_t serverCwnd{0};     //!< CongestionWindow trace calls seen on the listener's connection
    uint64_t serverRttCalls{0}; //!< RTT trace calls seen on the listener's connection
    uint64_t metrics{0};        //!< Metrics trace calls of the client
    uint64_t rtoCalls{0};       //!< RTO trace calls of the client
    Time lastRto{Seconds(0)};   //!< latest value of the RTO trace of the client
    uint64_t ptoCalls{0};       //!< PtoExpired trace calls of the client
    uint64_t clientBytes{0};    //!< bytes the client read
    uint64_t serverBytes{0};    //!< bytes the server read
    std::vector<int64_t> clientTxTimes; //!< times of the client's transmissions, in ns
    Ptr<QuicSocketBase> client;         //!< the client socket
    Ptr<QuicSocketBase> server;         //!< the server socket of the connection

    /**
     * Run the scenario.
     *
     * @param qlogDir the directory of the qlog files, empty for no log.
     * @param loss the packet loss rate of the link in each direction.
     */
    void Run(const std::string& qlogDir, double loss)
    {
        RngSeedManager::SetSeed(7);
        RngSeedManager::SetRun(3);
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
        Config::SetDefault("ns3::QuicL4Protocol::QlogDirectory", StringValue(qlogDir));
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper link;
        link.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
        link.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer devices = link.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper address;
        address.SetBase("10.7.6.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        for (uint32_t k = 0; k < 2; ++k)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
            em->SetRate(loss);
            em->AssignStreams(500 + k); // the same losses in every run of the process
            devices.Get(k)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        }

        TypeId factory = QuicSocketFactory::GetTypeId();
        Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
        listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listener->Listen();
        listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QlogRig::Accepted, this));
        // the traces connected to the listener follow the connection it accepts
        Ptr<QuicSocketBase> lq = DynamicCast<QuicSocketBase>(listener);
        lq->TraceConnectWithoutContext("Tx", MakeCallback(&QlogRig::OnServerTx, this));
        lq->TraceConnectWithoutContext("Rx", MakeCallback(&QlogRig::OnServerRx, this));
        lq->TraceConnectWithoutContext("CongestionWindow",
                                       MakeCallback(&QlogRig::OnServerCwnd, this));
        lq->TraceConnectWithoutContext("RTT", MakeCallback(&QlogRig::OnServerRtt, this));

        Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), factory);
        client = DynamicCast<QuicSocketBase>(socket);
        client->TraceConnectWithoutContext("Tx", MakeCallback(&QlogRig::OnClientTx, this));
        client->TraceConnectWithoutContext("Rx", MakeCallback(&QlogRig::OnClientRx, this));
        client->TraceConnectWithoutContext("PacketLost",
                                           MakeCallback(&QlogRig::OnClientLost, this));
        client->TraceConnectWithoutContext("PacketAcked",
                                           MakeCallback(&QlogRig::OnClientAcked, this));
        client->TraceConnectWithoutContext("Metrics", MakeCallback(&QlogRig::OnMetrics, this));
        client->TraceConnectWithoutContext("RTO", MakeCallback(&QlogRig::OnClientRto, this));
        client->TraceConnectWithoutContext("PtoExpired", MakeCallback(&QlogRig::OnClientPto, this));
        socket->SetRecvCallback(MakeCallback(&QlogRig::ClientRead, this));
        Simulator::Schedule(Seconds(0.1), [this, socket, interfaces]() {
            socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(0.6), &QlogRig::StartTransfer, this);
        Simulator::Stop(Seconds(30));
        Simulator::Run();
        Simulator::Destroy();
        Config::SetDefault("ns3::QuicL4Protocol::QlogDirectory", StringValue(""));
    }

  private:
    /** Write the data of both ends once the connection is open, trying again until it is. */
    void StartTransfer()
    {
        if (server == nullptr || server->GetSocketState() != QuicSocket::OPEN ||
            client->GetSocketState() != QuicSocket::OPEN)
        {
            Simulator::Schedule(MilliSeconds(100), &QlogRig::StartTransfer, this);
            return;
        }
        client->Send(Create<Packet>(150000));
        server->Send(Create<Packet>(150000));
    }

    void Accepted(Ptr<Socket> socket, const Address&)
    {
        server = DynamicCast<QuicSocketBase>(socket);
        socket->SetRecvCallback(MakeCallback(&QlogRig::ServerRead, this));
    }

    void ServerRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            serverBytes += packet->GetSize();
        }
    }

    void ClientRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()) && packet->GetSize() > 0)
        {
            clientBytes += packet->GetSize();
        }
    }

    void OnClientTx(Ptr<const Packet>, const QuicHeader&, Ptr<const QuicSocketBase>)
    {
        ++clientTx;
        clientTxTimes.push_back(Simulator::Now().GetNanoSeconds());
    }

    void OnClientRx(Ptr<const Packet>, const QuicHeader&, Ptr<const QuicSocketBase>)
    {
        ++clientRx;
    }

    void OnServerTx(Ptr<const Packet>, const QuicHeader&, Ptr<const QuicSocketBase>)
    {
        ++serverTx;
    }

    void OnServerRx(Ptr<const Packet>, const QuicHeader&, Ptr<const QuicSocketBase>)
    {
        ++serverRx;
    }

    void OnServerCwnd(uint32_t, uint32_t)
    {
        ++serverCwnd;
    }

    void OnServerRtt(Time, Time)
    {
        ++serverRttCalls;
    }

    void OnClientLost(uint64_t, uint32_t, std::string)
    {
        ++clientLost;
    }

    void OnClientAcked(uint64_t, uint32_t)
    {
        ++clientAcked;
    }

    void OnMetrics(Ptr<const QuicSocketState>)
    {
        ++metrics;
    }

    void OnClientRto(Time, Time now)
    {
        ++rtoCalls;
        lastRto = now;
    }

    void OnClientPto(uint32_t, Time)
    {
        ++ptoCalls;
    }
};

/**
 * A connection that loses packets: the events in the files match what the trace sources saw.
 */
class QlogConnectionTest : public TestCase
{
  public:
    QlogConnectionTest()
        : TestCase("events of a connection that loses packets")
    {
    }

  private:
    void DoRun() override
    {
        TempDir dir;
        QlogRig rig;
        rig.Run(dir.Path(), 0.03);
        NS_TEST_ASSERT_MSG_EQ(rig.serverBytes, 150000, "the server got the data");
        NS_TEST_ASSERT_MSG_EQ(rig.clientBytes, 150000, "the client got the data");
        auto files = dir.Files();
        NS_TEST_ASSERT_MSG_EQ(files.size(), 2, "a file for each end");
        std::string clientFile;
        std::string serverFile;
        for (const auto& f : files)
        {
            if (f.find("-client-") != std::string::npos)
            {
                clientFile = f;
            }
            if (f.find("-server-") != std::string::npos)
            {
                serverFile = f;
            }
        }
        NS_TEST_ASSERT_MSG_NE(clientFile, "", "client file");
        NS_TEST_ASSERT_MSG_NE(serverFile, "", "server file");
        // both ends of a connection share the group id, that is also in the file names
        const std::string suffix = clientFile.substr(clientFile.rfind("-"));
        NS_TEST_ASSERT_MSG_NE(serverFile.find(suffix), std::string::npos, "same group id");

        const std::string c = ReadFile(clientFile);
        const std::string s = ReadFile(serverFile);
        NS_TEST_EXPECT_MSG_EQ(Count(c, "\"name\":\"quic:packet_sent\""), rig.clientTx, "tx");
        NS_TEST_EXPECT_MSG_EQ(Count(c, "\"name\":\"quic:packet_received\""), rig.clientRx, "rx");
        NS_TEST_EXPECT_MSG_EQ(Count(s, "\"name\":\"quic:packet_sent\""), rig.serverTx, "tx");
        NS_TEST_EXPECT_MSG_EQ(Count(s, "\"name\":\"quic:packet_received\""), rig.serverRx, "rx");
        NS_TEST_EXPECT_MSG_GT(rig.clientLost, 0, "a link with loss declares packets lost");
        NS_TEST_EXPECT_MSG_EQ(Count(c, "\"name\":\"quic:packet_lost\""),
                              rig.clientLost,
                              "lost packets are logged once each");
        NS_TEST_EXPECT_MSG_GT(rig.clientAcked, 0, "acknowledgments");
        NS_TEST_EXPECT_MSG_GT(rig.metrics, 0, "metrics");
        NS_TEST_EXPECT_MSG_GT(Count(c, "\"name\":\"quic:recovery_metrics_updated\""),
                              0,
                              "metrics in the log");
        NS_TEST_EXPECT_MSG_EQ(Count(c, "\"name\":\"quic:connection_started\""), 1, "started");
        NS_TEST_EXPECT_MSG_EQ(Count(s, "\"name\":\"quic:connection_started\""), 1, "started");
        NS_TEST_EXPECT_MSG_EQ(Count(c, "\"name\":\"quic:parameters_set\""), 2, "local and remote");
        NS_TEST_EXPECT_MSG_EQ(Count(s, "\"name\":\"quic:parameters_set\""), 2, "local and remote");
        NS_TEST_EXPECT_MSG_GT(Count(c, "\"name\":\"quic:udp_datagrams_sent\""), 0, "datagrams");
        NS_TEST_EXPECT_MSG_GT(Count(c, "\"name\":\"quic:udp_datagrams_received\""), 0, "datagrams");
        NS_TEST_EXPECT_MSG_NE(c.find("\"trigger\":\"reordering_threshold\""),
                              std::string::npos,
                              "packet threshold");
        NS_TEST_EXPECT_MSG_NE(c.find("\"name\":\"quic:version_information\""),
                              std::string::npos,
                              "version");
        NS_TEST_EXPECT_MSG_NE(c.find("\"name\":\"quic:timer_updated\""),
                              std::string::npos,
                              "timer");

        // the RTO trace follows the timeout that is armed, not a constant
        NS_TEST_EXPECT_MSG_GT(rig.rtoCalls, 0, "RTO trace");
        NS_TEST_EXPECT_MSG_LT(rig.lastRto, Seconds(2), "the timeout of a 20 ms path");
        NS_TEST_EXPECT_MSG_GT(rig.lastRto, MilliSeconds(20), "above the RTT");

        // the trace sources of the listener are on the connection it accepted
        NS_TEST_EXPECT_MSG_GT(rig.serverTx, 0, "Tx of the accepted connection");
        NS_TEST_EXPECT_MSG_GT(rig.serverCwnd, 0, "CongestionWindow of the accepted connection");
        NS_TEST_EXPECT_MSG_GT(rig.serverRttCalls, 0, "RTT of the accepted connection");
    }
};

/**
 * A link that loses a quarter of the packets: probe timeouts fire and are logged.
 */
class QlogProbeTimeoutTest : public TestCase
{
  public:
    QlogProbeTimeoutTest()
        : TestCase("probe timeouts on a link with heavy loss")
    {
    }

  private:
    void DoRun() override
    {
        TempDir dir;
        QlogRig rig;
        rig.Run(dir.Path(), 0.25);
        NS_TEST_ASSERT_MSG_GT(rig.ptoCalls, 0, "the probe timeout fired");
        std::string log;
        for (const auto& f : dir.Files())
        {
            if (f.find("-client-") != std::string::npos)
            {
                log = ReadFile(f);
            }
        }
        NS_TEST_EXPECT_MSG_GT(Count(log, "\"timer_type\":\"pto\",\"event_type\":\"expired\""),
                              0,
                              "the expiry is logged");
        NS_TEST_EXPECT_MSG_GT(Count(log, "\"trigger\":\"pto_expired\"") +
                                  Count(log, "\"trigger\":\"time_threshold\"") +
                                  Count(log, "\"trigger\":\"reordering_threshold\""),
                              0,
                              "lost packets");
    }
};

/**
 * Logging changes nothing the simulation does: the times and the number of packets are those of
 * a run without it.
 */
class QlogNoEffectTest : public TestCase
{
  public:
    QlogNoEffectTest()
        : TestCase("the log does not change the simulation")
    {
    }

  private:
    void DoRun() override
    {
        QlogRig off;
        off.Run("", 0.03);
        TempDir dir;
        QlogRig on;
        on.Run(dir.Path(), 0.03);
        NS_TEST_ASSERT_MSG_EQ(on.clientTxTimes.size(), off.clientTxTimes.size(), "packets");
        NS_TEST_ASSERT_MSG_EQ(on.serverTx, off.serverTx, "server packets");
        NS_TEST_EXPECT_MSG_EQ((on.clientTxTimes == off.clientTxTimes), true, "same send times");
        NS_TEST_EXPECT_MSG_EQ(on.clientLost, off.clientLost, "same losses");
    }
};

class QuicQlogTestSuite : public TestSuite
{
  public:
    QuicQlogTestSuite()
        : TestSuite("quic-qlog", Type::UNIT)
    {
        AddTestCase(new QlogFormatTest, TestCase::Duration::QUICK);
        AddTestCase(new QlogHeaderTest, TestCase::Duration::QUICK);
        AddTestCase(new QlogFramesTest, TestCase::Duration::QUICK);
        AddTestCase(new QlogRecordTest, TestCase::Duration::QUICK);
        AddTestCase(new QlogConnectionTest, TestCase::Duration::QUICK);
        AddTestCase(new QlogProbeTimeoutTest, TestCase::Duration::QUICK);
        AddTestCase(new QlogNoEffectTest, TestCase::Duration::QUICK);
    }
};

QuicQlogTestSuite g_quicQlogTestSuite;

} // namespace
