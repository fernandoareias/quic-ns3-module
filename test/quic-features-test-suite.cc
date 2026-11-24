/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module - feature evidence suite ("quic-features").
 *
 * Complements quic-test-suite.cc. Each case demonstrates one implemented behaviour:
 *   wire formats of every frame added or extended (ACK, ACK_FREQUENCY, IMMEDIATE_ACK,
 *   NEW/RETIRE_CONNECTION_ID, MAX_STREAMS, STREAMS_BLOCKED, RESET/STOP_SENDING, PATH_*),
 *   transport parameters, congestion-control defaults, scheduler conservation and fairness,
 *   and end-to-end behaviour: BBR/NewReno/CUBIC under uniform and burst loss, writes during the
 *   handshake, bounded pending writes, throughput, round-robin versus FIFO latency,
 *   ACK-frequency reduction of ACK traffic, and several concurrent connections on one listener.
 */

#include "../helper/quic-helper.h"
#include "../model/quic-bbr.h"
#include "../model/quic-congestion-ops.h"
#include "../model/quic-cubic.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-l5-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-socket-tx-buffer.h"
#include "../model/quic-socket-tx-edf-scheduler.h"
#include "../model/quic-socket-tx-pfifo-scheduler.h"
#include "../model/quic-socket-tx-roundrobin-scheduler.h"
#include "../model/quic-socket-tx-streamfifo-scheduler.h"
#include "../model/quic-stream-id-tag.h"
#include "../model/quic-subheader.h"
#include "../model/quic-transport-parameters.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/test.h"

#include <map>
#include <set>

using namespace ns3;

namespace
{

uint64_t
ServerStreamId(uint32_t n)
{
    return 4 * (n - 1) + 1;
}

uint32_t
LogicalStream(uint64_t id)
{
    return (uint32_t)(id >> 2) + 1;
}

void
OpenStreamLimits(void)
{
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(8));
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdUni", UintegerValue(8));
}

template <typename T>
T
RoundTrip(const T& in)
{
    Ptr<Packet> p = Create<Packet>();
    p->AddHeader(in);
    T out;
    p->RemoveHeader(out);
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Wire formats
// ---------------------------------------------------------------------------

class FeatAckFrequencyWireTest : public TestCase
{
  public:
    FeatAckFrequencyWireTest()
        : TestCase("wire: ACK_FREQUENCY and IMMEDIATE_ACK round trip")
    {
    }

  private:
    void DoRun() override
    {
        QuicSubheader af = RoundTrip(QuicSubheader::CreateAckFrequency(7, 41, 25000, 1));
        NS_TEST_ASSERT_MSG_EQ(af.GetFrameType(), (uint8_t)QuicSubheader::ACK_FREQUENCY, "type");
        NS_TEST_ASSERT_MSG_EQ(af.GetAckFreqSequence(), 7u, "sequence");
        NS_TEST_ASSERT_MSG_EQ(af.GetAckFreqThreshold(), 41u, "threshold");
        NS_TEST_ASSERT_MSG_EQ(af.GetAckFreqMaxDelayUs(), 25000u, "max delay");
        NS_TEST_ASSERT_MSG_EQ(af.GetAckFreqReordering(), 1u, "reordering threshold");
        QuicSubheader ia = RoundTrip(QuicSubheader::CreateImmediateAck());
        NS_TEST_ASSERT_MSG_EQ(ia.GetFrameType(), (uint8_t)QuicSubheader::IMMEDIATE_ACK, "type");
    }
};

class FeatConnectionIdWireTest : public TestCase
{
  public:
    FeatConnectionIdWireTest()
        : TestCase("wire: NEW_CONNECTION_ID with retire_prior_to and token, RETIRE_CONNECTION_ID")
    {
    }

  private:
    void DoRun() override
    {
        QuicSubheader n = RoundTrip(QuicSubheader::CreateNewConnectionId(3,
                                                                         2,
                                                                         0xABCDEF0123456789ULL,
                                                                         0x1111222233334444ULL,
                                                                         0x5555666677778888ULL));
        NS_TEST_ASSERT_MSG_EQ(n.GetSequence(), 3u, "sequence");
        NS_TEST_ASSERT_MSG_EQ(n.GetRetirePriorTo(), 2u, "retire prior to");
        NS_TEST_ASSERT_MSG_EQ(n.GetConnectionId(), 0xABCDEF0123456789ULL, "cid");
        NS_TEST_ASSERT_MSG_EQ(n.GetResetTokenHi(), 0x1111222233334444ULL, "token hi");
        NS_TEST_ASSERT_MSG_EQ(n.GetResetTokenLo(), 0x5555666677778888ULL, "token lo");
        QuicSubheader r = RoundTrip(QuicSubheader::CreateRetireConnectionId(9));
        NS_TEST_ASSERT_MSG_EQ(r.GetFrameType(),
                              (uint8_t)QuicSubheader::RETIRE_CONNECTION_ID,
                              "type");
        NS_TEST_ASSERT_MSG_EQ(r.GetSequence(), 9u, "retired sequence");
    }
};

class FeatControlFramesWireTest : public TestCase
{
  public:
    FeatControlFramesWireTest()
        : TestCase("wire: MAX_STREAMS, STREAMS_BLOCKED, RESET_STREAM, STOP_SENDING, PATH_CHALLENGE "
                   "and PATH_RESPONSE, MAX_DATA")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ(RoundTrip(QuicSubheader::CreateMaxStreamId(123456)).GetMaxStreamId(),
                              123456u,
                              "MAX_STREAMS");
        NS_TEST_ASSERT_MSG_EQ(RoundTrip(QuicSubheader::CreateStreamIdBlocked(77)).GetStreamId(),
                              77u,
                              "STREAMS_BLOCKED");
        QuicSubheader rs = RoundTrip(QuicSubheader::CreateRstStream(5, 11, 4096));
        NS_TEST_ASSERT_MSG_EQ(rs.GetStreamId(), 5u, "RESET stream");
        NS_TEST_ASSERT_MSG_EQ(rs.GetErrorCode(), 11u, "RESET error");
        QuicSubheader ss = RoundTrip(QuicSubheader::CreateStopSending(9, 7));
        NS_TEST_ASSERT_MSG_EQ(ss.GetStreamId(), 9u, "STOP_SENDING stream");
        NS_TEST_ASSERT_MSG_EQ(ss.GetErrorCode(), 7u, "STOP_SENDING error");
        NS_TEST_ASSERT_MSG_EQ(
            RoundTrip(QuicSubheader::CreatePathChallenge(0x0102030405060708ULL)).GetData(),
            0x0102030405060708ULL,
            "PATH_CHALLENGE");
        NS_TEST_ASSERT_MSG_EQ(
            RoundTrip(QuicSubheader::CreatePathResponse(0x1122334455667788ULL)).GetData(),
            0x1122334455667788ULL,
            "PATH_RESPONSE");
        NS_TEST_ASSERT_MSG_EQ(RoundTrip(QuicSubheader::CreateMaxData(1ULL << 33)).GetMaxData(),
                              1ULL << 33,
                              "MAX_DATA 62-bit varint");
        QuicSubheader sd = RoundTrip(QuicSubheader::CreateMaxStreamData(13, 99999));
        NS_TEST_ASSERT_MSG_EQ(sd.GetStreamId(), 13u, "MAX_STREAM_DATA stream");
        NS_TEST_ASSERT_MSG_EQ(sd.GetMaxStreamData(), 99999u, "MAX_STREAM_DATA value");
    }
};

namespace
{

std::vector<uint8_t>
FeatBytes(const Header& h)
{
    Ptr<Packet> p = Create<Packet>();
    p->AddHeader(h);
    std::vector<uint8_t> b(p->GetSize());
    p->CopyData(b.data(), b.size());
    return b;
}

} // namespace

class FeatAckRangesWireTest : public TestCase
{
  public:
    FeatAckRangesWireTest()
        : TestCase("wire: ACK frame with several gaps keeps its ranges")
    {
    }

  private:
    void DoRun() override
    {
        // packets 996-1000, 990-993 and 980-985 received: in memory the ranges are packet numbers
        std::vector<uint32_t> gaps = {995, 989};
        std::vector<uint32_t> blocks = {993, 985};
        QuicSubheader ack = RoundTrip(QuicSubheader::CreateAck(1000, 250, 980, gaps, blocks));
        NS_TEST_ASSERT_MSG_EQ(ack.GetLargestAcknowledged(), 1000u, "largest");
        NS_TEST_ASSERT_MSG_EQ(ack.GetAckDelay(), 250u, "delay");
        NS_TEST_ASSERT_MSG_EQ(ack.GetFirstAckBlock(), 980u, "ack floor");
        NS_TEST_ASSERT_MSG_EQ(ack.GetGaps().size(), 2u, "gaps");
        NS_TEST_ASSERT_MSG_EQ(ack.GetAdditionalAckBlocks().size(), 2u, "blocks");
        for (size_t i = 0; i < 2; ++i)
        {
            NS_TEST_ASSERT_MSG_EQ(ack.GetGaps()[i], gaps[i], "gap " << i);
            NS_TEST_ASSERT_MSG_EQ(ack.GetAdditionalAckBlocks()[i], blocks[i], "block " << i);
        }
        // a single range, and ranges one packet apart
        std::vector<uint32_t> noGaps, noBlocks;
        QuicSubheader one = RoundTrip(QuicSubheader::CreateAck(5, 0, 3, noGaps, noBlocks));
        NS_TEST_ASSERT_MSG_EQ(one.GetFirstAckBlock(), 3u, "single range floor");
        NS_TEST_ASSERT_MSG_EQ(one.GetGaps().size(), 0u, "single range has no gap");
        std::vector<uint32_t> g2 = {8}, b2 = {6}; // 9-10 received, 8 missing, 4-6 received
        QuicSubheader two = RoundTrip(QuicSubheader::CreateAck(10, 0, 4, g2, b2));
        NS_TEST_ASSERT_MSG_EQ(two.GetGaps()[0], 8u, "gap of one packet");
        NS_TEST_ASSERT_MSG_EQ(two.GetAdditionalAckBlocks()[0], 6u, "second range end");
        NS_TEST_ASSERT_MSG_EQ(two.GetFirstAckBlock(), 4u, "second range start");
    }
};

/**
 * The bytes of frames that RFC 9000 s19 defines: counts relative to the previous range in ACK,
 * error codes as variable-length integers, the frame type in the transport CONNECTION_CLOSE, the
 * length of a connection id.
 */
class FeatRfcWireBytesTest : public TestCase
{
  public:
    FeatRfcWireBytesTest()
        : TestCase("wire: ACK ranges, error codes, CONNECTION_CLOSE and NEW_CONNECTION_ID are laid "
                   "out as in RFC 9000 s19")
    {
    }

  private:
    void Expect(const char* what, const Header& h, std::vector<uint8_t> want)
    {
        std::vector<uint8_t> got = FeatBytes(h);
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), what << ": size");
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k], (uint32_t)want[k], what << ": byte " << k);
        }
    }

    void DoRun() override
    {
        // largest 1000, delay 250, ranges 996-1000, 990-993, 980-985 (RFC 9000 s19.3.1: count 2,
        // first range 4, gap 1 / range 3, gap 3 / range 5)
        std::vector<uint32_t> gaps = {995, 989}, blocks = {993, 985};
        Expect("ACK",
               QuicSubheader::CreateAck(1000, 250, 980, gaps, blocks),
               {0x02, 0x43, 0xE8, 0x40, 0xFA, 0x02, 0x04, 0x01, 0x03, 0x03, 0x05});
        std::vector<uint32_t> none;
        Expect("ACK, one range",
               QuicSubheader::CreateAck(5, 0, 5, none, none),
               {0x02, 0x05, 0x00, 0x00, 0x00});
        // transport CONNECTION_CLOSE: error code, frame type, reason length, reason
        Expect("CONNECTION_CLOSE",
               QuicSubheader::CreateConnectionClose(0x0a, "x"),
               {0x1c, 0x0a, 0x00, 0x01, 'x'});
        // application CONNECTION_CLOSE has no frame type
        Expect("CONNECTION_CLOSE (application)",
               QuicSubheader::CreateApplicationClose(0x0a, "x"),
               {0x1d, 0x0a, 0x01, 'x'});
        Expect("RESET_STREAM",
               QuicSubheader::CreateRstStream(5, 11, 4096),
               {0x04, 0x05, 0x0b, 0x50, 0x00});
        Expect("STOP_SENDING", QuicSubheader::CreateStopSending(9, 7), {0x05, 0x09, 0x07});
        Expect("NEW_CONNECTION_ID",
               QuicSubheader::CreateNewConnectionId(3,
                                                    2,
                                                    0x0102030405060708ULL,
                                                    0x1111111111111111ULL,
                                                    0x2222222222222222ULL),
               {0x18, 0x03, 0x02, 0x08, 1,    2,    3,    4,    5,    6,
                7,    8,    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22});
        // and they read back
        QuicSubheader cc = RoundTrip(QuicSubheader::CreateConnectionClose(0x0a, "bad"));
        NS_TEST_ASSERT_MSG_EQ(cc.GetErrorCode(), 0x0au, "close error");
        NS_TEST_ASSERT_MSG_EQ(cc.GetReasonPhraseLength(), 3u, "close reason");
        QuicSubheader big = RoundTrip(QuicSubheader::CreateRstStream(5, 300, 4096));
        NS_TEST_ASSERT_MSG_EQ(big.GetErrorCode(), 300u, "two-byte varint error code");
    }
};

/**
 * The first byte of the packet headers as RFC 9000 s17 lays it out: a short header is 0 | Fixed Bit
 * | Spin | 00 | Key Phase | Packet Number Length, a long header 1 | Fixed Bit | Type | 00 | Packet
 * Number Length, and a Version Negotiation packet is the long header whose version is 0.
 */
class FeatHeaderWireTest : public TestCase
{
  public:
    FeatHeaderWireTest()
        : TestCase("wire: packet header first byte, key phase, spin bit and packet number length "
                   "as in RFC 9000 s17")
    {
    }

  private:
    void Expect(const char* what, const QuicHeader& h, std::vector<uint8_t> want)
    {
        std::vector<uint8_t> got = FeatBytes(h);
        NS_TEST_ASSERT_MSG_EQ(got.size(), want.size(), what << ": size");
        for (size_t k = 0; k < std::min(got.size(), want.size()); ++k)
        {
            NS_TEST_ASSERT_MSG_EQ((uint32_t)got[k], (uint32_t)want[k], what << ": byte " << k);
        }
        NS_TEST_ASSERT_MSG_EQ(RoundTrip(h) == h, true, what << ": round trip");
    }

    void DoRun() override
    {
        const uint64_t cid = 0x0102030405060708ULL;
        // spin 1, key phase 1, 1-byte packet number
        Expect("short, spin and key phase",
               QuicHeader::CreateShort(cid, SequenceNumber32(5), true, true, true),
               {0x64, 1, 2, 3, 4, 5, 6, 7, 8, 0x05});
        // 2-byte and 4-byte packet numbers
        Expect("short, 2-byte number",
               QuicHeader::CreateShort(cid, SequenceNumber32(300), true, false, false),
               {0x41, 1, 2, 3, 4, 5, 6, 7, 8, 0x01, 0x2c});
        Expect("short, 4-byte number",
               QuicHeader::CreateShort(cid, SequenceNumber32(70000), true, false, false),
               {0x43, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x01, 0x11, 0x70});
        // without the connection id (OmitConnectionId): flagged in a reserved bit, no id bytes
        Expect("short, no connection id",
               QuicHeader::CreateShort(cid, SequenceNumber32(5), false, false, false),
               {0x48, 0x05});
        Expect("Initial",
               QuicHeader::CreateInitial(cid, QUIC_VERSION, SequenceNumber32(1)),
               {0xC3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1});
        Expect("0-RTT",
               QuicHeader::Create0RTT(cid, QUIC_VERSION, SequenceNumber32(1)),
               {0xD3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1});
        Expect("Handshake",
               QuicHeader::CreateHandshake(cid, QUIC_VERSION, SequenceNumber32(1)),
               {0xE3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1});
        std::vector<uint32_t> versions = {QUIC_VERSION};
        QuicHeader vn =
            QuicHeader::CreateVersionNegotiation(cid, QUIC_VERSION_NEGOTIATION, versions);
        Expect("Version Negotiation", vn, {0xC0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0});
        NS_TEST_ASSERT_MSG_EQ(RoundTrip(vn).IsVersionNegotiation(),
                              true,
                              "version 0 is a Version Negotiation packet");
        NS_TEST_ASSERT_MSG_EQ(
            RoundTrip(QuicHeader::CreateInitial(cid, QUIC_VERSION, SequenceNumber32(1)))
                .IsInitial(),
            true,
            "an Initial is not mistaken for one");
        // a short header keeps its packet number length where the long types live: it must never
        // read as one of them
        for (uint32_t pn : {5u, 300u, 70000u})
        {
            QuicHeader sh =
                RoundTrip(QuicHeader::CreateShort(cid, SequenceNumber32(pn), true, false, false));
            NS_TEST_ASSERT_MSG_EQ(sh.IsShort(), true, "short header, packet number " << pn);
            NS_TEST_ASSERT_MSG_EQ((sh.IsInitial() || sh.IsRetry() || sh.IsHandshake() ||
                                   sh.IsORTT() || sh.IsVersionNegotiation()),
                                  false,
                                  "a short header is not a long one, packet number " << pn);
        }
        // reserved versions: 0x?a?a?a?a only
        Ptr<QuicSocketBase> any = CreateObject<QuicSocketBase>();
        NS_TEST_ASSERT_MSG_EQ(any->CheckVersionNegotiation(0x1a2a3a4a), true, "reserved version");
        NS_TEST_ASSERT_MSG_EQ(any->CheckVersionNegotiation(0xFFFFFFFF),
                              false,
                              "not a reserved version");
    }
};

class FeatTransportParametersTest : public TestCase
{
  public:
    FeatTransportParametersTest()
        : TestCase("transport parameters: round trip, min_ack_delay, migration allowed by default")
    {
    }

  private:
    void DoRun() override
    {
        QuicTransportParameters tp;
        NS_TEST_ASSERT_MSG_EQ((int)tp.GetDisableActiveMigration(),
                              0,
                              "migration must be allowed by default (msquic)");
        tp.SetMinAckDelay(1000);
        tp.SetMaxAckDelay(25);
        tp.SetInitialMaxData(123456);
        tp.SetInitialMaxStreamData(65536);
        tp.SetIdleTimeout(30);
        tp.SetStatelessResetToken(0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL);
        QuicTransportParameters out = RoundTrip(tp);
        NS_TEST_ASSERT_MSG_EQ(out.GetMinAckDelay(), 1000u, "min_ack_delay");
        NS_TEST_ASSERT_MSG_EQ(out.GetMaxAckDelay(), 25u, "max_ack_delay");
        NS_TEST_ASSERT_MSG_EQ(out.GetInitialMaxData(), 123456u, "initial_max_data");
        NS_TEST_ASSERT_MSG_EQ(out.GetInitialMaxStreamData(), 65536u, "initial_max_stream_data");
        NS_TEST_ASSERT_MSG_EQ(out.GetIdleTimeout(), 30u, "idle timeout");
        NS_TEST_ASSERT_MSG_EQ(out.GetStatelessResetTokenHi(), 0x1122334455667788ULL, "token hi");
        NS_TEST_ASSERT_MSG_EQ(out.GetStatelessResetTokenLo(), 0x99AABBCCDDEEFF00ULL, "token lo");
    }
};

// ---------------------------------------------------------------------------
// Congestion control defaults
// ---------------------------------------------------------------------------

class FeatCongestionDefaultsTest : public TestCase
{
  public:
    FeatCongestionDefaultsTest()
        : TestCase("congestion control: CUBIC without HyStart (msquic default), BBR and NewReno "
                   "available")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<QuicCubic> cubic = CreateObject<QuicCubic>();
        BooleanValue hystart;
        cubic->GetAttribute("HyStart", hystart);
        NS_TEST_ASSERT_MSG_EQ(hystart.Get(), false, "msquic ships HyStart disabled");
        NS_TEST_ASSERT_MSG_NE(CreateObject<QuicBbr>(), nullptr, "BBR");
        NS_TEST_ASSERT_MSG_EQ(TypeId::LookupByName("ns3::QuicCongestionControl").GetName(),
                              "ns3::QuicCongestionControl",
                              "NewReno");
        Simulator::Destroy();
    }
};

// ---------------------------------------------------------------------------
// Schedulers: conservation and fairness
// ---------------------------------------------------------------------------

static Ptr<QuicSocketTxItem>
FeatItem(uint64_t stream, uint64_t offset)
{
    Ptr<QuicSocketTxItem> it = CreateObject<QuicSocketTxItem>();
    it->m_packet = Create<Packet>(100);
    it->m_packet->AddHeader(
        QuicSubheader::CreateStreamSubHeader(stream, offset, 100, offset != 0, true, false));
    it->m_isStream = true;
    return it;
}

static std::vector<std::pair<uint64_t, uint64_t>>
FeatDrain(Ptr<QuicSocketTxScheduler> sched)
{
    std::vector<std::pair<uint64_t, uint64_t>> order;
    while (true)
    {
        Ptr<QuicSocketTxItem> out = sched->GetNewSegment(1500);
        if (out == nullptr || out->m_packet == nullptr || out->m_packet->GetSize() == 0)
        {
            break;
        }
        Ptr<Packet> pkt = out->m_packet->Copy();
        while (pkt->GetSize() > 0)
        {
            QuicSubheader qsb;
            pkt->RemoveHeader(qsb);
            uint64_t len = std::min<uint64_t>(qsb.GetLength(), pkt->GetSize());
            order.push_back({qsb.GetStreamId(), len});
            pkt->RemoveAtStart(len);
        }
    }
    return order;
}

class FeatSchedulerConservationTest : public TestCase
{
  public:
    FeatSchedulerConservationTest()
        : TestCase("schedulers: FIFO, per-stream FIFO, priority FIFO and round-robin lose no byte")
    {
    }

  private:
    void Check(Ptr<QuicSocketTxScheduler> s, const char* name)
    {
        for (uint32_t i = 0; i < 40; ++i)
        {
            s->Add(FeatItem(1, i * 100), false);
            s->Add(FeatItem(5, i * 100), false);
            s->Add(FeatItem(9, i * 100), false);
        }
        std::map<uint64_t, uint64_t> bytes;
        for (auto& f : FeatDrain(s))
        {
            bytes[f.first] += f.second;
        }
        NS_TEST_ASSERT_MSG_EQ(bytes[1], 4000u, name << ": stream 1 bytes");
        NS_TEST_ASSERT_MSG_EQ(bytes[5], 4000u, name << ": stream 5 bytes");
        NS_TEST_ASSERT_MSG_EQ(bytes[9], 4000u, name << ": stream 9 bytes");
    }

    void DoRun() override
    {
        Check(CreateObject<QuicSocketTxScheduler>(), "fifo");
        Check(CreateObject<QuicSocketTxStreamFifoScheduler>(), "stream fifo");
        Check(CreateObject<QuicSocketTxPFifoScheduler>(), "pfifo");
        Check(CreateObject<QuicSocketTxRoundRobinScheduler>(), "round-robin");
    }
};

/**
 * A frame that carries no data (a control frame, or a STREAM frame with only FIN) cannot be cut in
 * two. When it does not fit in the room left after the ACK frame, it waits for the next packet;
 * splitting it used to read a byte from an empty payload and crash the retransmission of a lost
 * MAX_DATA.
 */
class FeatSchedulerDataLessFrameTest : public TestCase
{
  public:
    FeatSchedulerDataLessFrameTest()
        : TestCase("schedulers: a frame without data that does not fit waits for the next packet")
    {
    }

  private:
    static Ptr<QuicSocketTxItem> Frame(const QuicSubheader& sub)
    {
        Ptr<QuicSocketTxItem> it = CreateObject<QuicSocketTxItem>();
        it->m_packet = Create<Packet>();
        it->m_packet->AddHeader(sub);
        it->m_isStream = true;
        return it;
    }

    void Check(Ptr<QuicSocketTxScheduler> s, Ptr<QuicSocketTxItem> frame, const char* name)
    {
        uint32_t size = frame->m_packet->GetSize();
        NS_TEST_ASSERT_MSG_GT(size, 4u, name << ": the frame is larger than the room offered");
        s->Add(frame, true);
        Ptr<QuicSocketTxItem> out = s->GetNewSegment(4);
        NS_TEST_ASSERT_MSG_NE(out, nullptr, name << ": a segment is returned");
        NS_TEST_ASSERT_MSG_EQ(out->m_packet->GetSize(), 0u, name << ": nothing fits in 4 bytes");
        NS_TEST_ASSERT_MSG_EQ(s->AppSize(), size, name << ": the frame is still queued");
        out = s->GetNewSegment(1459);
        NS_TEST_ASSERT_MSG_EQ(out->m_packet->GetSize(),
                              size,
                              name << ": it goes out whole in the next packet");
        NS_TEST_ASSERT_MSG_EQ(s->AppSize(), 0u, name << ": the queue is empty");
    }

    void DoRun() override
    {
        Check(CreateObject<QuicSocketTxScheduler>(),
              Frame(QuicSubheader::CreateMaxData(1 << 24)),
              "MAX_DATA");
        Check(CreateObject<QuicSocketTxScheduler>(),
              Frame(QuicSubheader::CreateStreamSubHeader(4000, 123456, 0, true, true, true)),
              "STREAM with FIN only");
    }
};

class FeatRoundRobinFairnessTest : public TestCase
{
  public:
    FeatRoundRobinFairnessTest()
        : TestCase("round-robin: two backlogged streams share the first 35 KB equally")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<QuicSocketTxRoundRobinScheduler> rr = CreateObject<QuicSocketTxRoundRobinScheduler>();
        for (uint32_t i = 0; i < 300; ++i)
        {
            rr->Add(FeatItem(1, i * 100), false);
            rr->Add(FeatItem(5, i * 100), false);
        }
        uint64_t total = 0, b1 = 0, b5 = 0;
        for (auto& f : FeatDrain(rr))
        {
            total += f.second;
            if (total <= 35000)
            {
                (f.first == 1 ? b1 : b5) += f.second;
            }
        }
        NS_TEST_ASSERT_MSG_EQ(total, 60000u, "all bytes drained");
        int64_t share1 = b1, share5 = b5;
        NS_TEST_ASSERT_MSG_LT(std::abs(share1 - share5),
                              12500,
                              "first 35 KB must be shared (got " << share1 << "/" << share5 << ")");
        NS_TEST_ASSERT_MSG_GT(share1, 0, "stream 1 served");
        NS_TEST_ASSERT_MSG_GT(share5, 0, "stream 5 served");
    }
};

class FeatStreamFifoUnfairnessTest : public TestCase
{
  public:
    FeatStreamFifoUnfairnessTest()
        : TestCase(
              "stream FIFO (msquic default): the first backlogged stream drains before the second")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<QuicSocketTxStreamFifoScheduler> f = CreateObject<QuicSocketTxStreamFifoScheduler>();
        for (uint32_t i = 0; i < 100; ++i)
        {
            f->Add(FeatItem(1, i * 100), false);
        }
        for (uint32_t i = 0; i < 100; ++i)
        {
            f->Add(FeatItem(5, i * 100), false);
        }
        uint64_t before = 0;
        bool seen = false;
        for (auto& fr : FeatDrain(f))
        {
            if (fr.first == 5)
            {
                seen = true;
            }
            if (!seen)
            {
                before += fr.second;
            }
        }
        size_t firstOfTwo = (size_t)before / 100;
        NS_TEST_ASSERT_MSG_GT(firstOfTwo, 90u, "stream 5 only after (almost) all of stream 1");
    }
};

// ---------------------------------------------------------------------------
// End-to-end rig
// ---------------------------------------------------------------------------

struct FeatStat
{
    uint64_t bytes{0};
    Time first{Time::Max()};
    Time last{Seconds(0)};
};

class FeatRig
{
  public:
    std::string cc{"ns3::QuicCubic"};
    TypeId sched{QuicSocketTxStreamFifoScheduler::GetTypeId()};
    std::string rate{"10Mbps"};
    std::string delay{"20ms"};
    double uniformLoss{0};
    double burstStartRate{0};
    uint32_t nClients{1};
    double clientSpacing{0.01}; //!< seconds between the Connect() calls of successive clients
    uint64_t serverBytesPerStream{300000};
    uint32_t serverStreams{3};
    bool serverCloses{true};
    Time stopAt{Seconds(120)};
    uint32_t seedRun{3};
    std::string queue{""};     //!< bottleneck queue size, e.g. "2000p"; empty keeps the default
    uint32_t maxStreamData{0}; //!< 0 keeps the module default

    NodeContainer nodes;
    NetDeviceContainer dev;
    Ptr<Socket> listen;
    std::vector<Ptr<Socket>> clients;
    std::vector<Ptr<Socket>> accepted;
    std::vector<std::map<uint32_t, FeatStat>> rx;
    std::vector<bool> corrupt;
    std::function<void(Ptr<Socket>)> onAccept;
    std::function<void(uint32_t, Ptr<Socket>)> onClientConnected;
    uint64_t dataPacketsToClient{0};
    uint64_t packetsToServer{0};
    uint64_t lateTx{0}; //!< packets sent by either side after t = 30 s
    Ipv4Address serverAddr;

    void Build()
    {
        OpenStreamLimits();
        if (maxStreamData > 0)
        {
            Config::SetDefault("ns3::QuicSocketBase::MaxStreamData", UintegerValue(maxStreamData));
            Config::SetDefault("ns3::QuicSocketBase::MaxData", UintegerValue(maxStreamData * 4));
        }
        Config::SetDefault("ns3::QuicL4Protocol::SocketType",
                           TypeIdValue(TypeId::LookupByName(cc)));
        Config::SetDefault("ns3::QuicSocketBase::SchedulingPolicy", TypeIdValue(sched));
        RngSeedManager::SetSeed(1);
        RngSeedManager::SetRun(seedRun);
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue(rate));
        p2p.SetChannelAttribute("Delay", StringValue(delay));
        if (!queue.empty())
        {
            p2p.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue(queue));
        }
        dev = p2p.Install(nodes);
        if (uniformLoss > 0)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetAttribute("ErrorRate", DoubleValue(uniformLoss));
            em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
            dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        }
        else if (burstStartRate > 0)
        {
            Ptr<BurstErrorModel> bm = CreateObject<BurstErrorModel>();
            bm->SetAttribute("ErrorRate", DoubleValue(burstStartRate));
            Ptr<UniformRandomVariable> len = CreateObject<UniformRandomVariable>();
            len->SetAttribute("Min", DoubleValue(1));
            len->SetAttribute("Max", DoubleValue(7));
            bm->SetRandomBurstSize(len);
            dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(bm));
        }
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.1.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        serverAddr = ifs.GetAddress(0);

        dev.Get(0)->TraceConnectWithoutContext("PhyTxEnd",
                                               MakeCallback(&FeatRig::CountToClient, this));
        dev.Get(1)->TraceConnectWithoutContext("PhyTxEnd",
                                               MakeCallback(&FeatRig::CountToServer, this));

        TypeId tid = QuicSocketFactory::GetTypeId();
        listen = Socket::CreateSocket(nodes.Get(0), tid);
        listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        listen->Listen();
        listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                  MakeCallback(&FeatRig::Accept, this));
        rx.resize(nClients);
        corrupt.assign(nClients, false);
        for (uint32_t i = 0; i < nClients; ++i)
        {
            Ptr<Socket> c = Socket::CreateSocket(nodes.Get(1), tid);
            c->SetRecvCallback(MakeCallback(&FeatRig::ClientRead, this));
            clients.push_back(c);
            Simulator::Schedule(Seconds(0.1 + clientSpacing * i), [this, c, i]() {
                c->Connect(InetSocketAddress(serverAddr, 4433));
                if (onClientConnected)
                {
                    onClientConnected(i, c);
                }
            });
        }
    }

    void Run()
    {
        Simulator::Stop(stopAt);
        Simulator::Run();
        Simulator::Destroy();
    }

    static void SendPattern(Ptr<Socket> s, uint64_t streamId, uint64_t bytes)
    {
        for (uint64_t off = 0; off < bytes; off += 1000)
        {
            uint32_t n = (uint32_t)std::min<uint64_t>(1000, bytes - off);
            std::vector<uint8_t> buf(n);
            for (uint32_t i = 0; i < n; ++i)
            {
                buf[i] = (uint8_t)((off + i) & 0xff);
            }
            s->Send(Create<Packet>(buf.data(), n), streamId);
        }
    }

    void CountToClient(Ptr<const Packet> p)
    {
        if (Simulator::Now() > Seconds(30))
        {
            ++lateTx;
        }
        if (p->GetSize() > 300)
        {
            ++dataPacketsToClient;
        }
    }

    void CountToServer(Ptr<const Packet>)
    {
        ++packetsToServer;
        if (Simulator::Now() > Seconds(30))
        {
            ++lateTx;
        }
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        accepted.push_back(s);
        if (onAccept)
        {
            onAccept(s);
            return;
        }
        for (uint32_t sid = 1; sid <= serverStreams; ++sid)
        {
            SendPattern(s, ServerStreamId(sid), serverBytesPerStream);
        }
        if (serverCloses)
        {
            s->Close();
        }
    }

    void ClientRead(Ptr<Socket> s)
    {
        uint32_t idx = 0;
        for (; idx < clients.size() && clients[idx] != s; ++idx)
        {
        }
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            std::vector<uint8_t> raw(p->GetSize());
            p->CopyData(raw.data(), raw.size());
            for (ByteTagIterator it = p->GetByteTagIterator(); it.HasNext();)
            {
                ByteTagIterator::Item item = it.Next();
                if (item.GetTypeId() != QuicStreamIdTag::GetTypeId())
                {
                    continue;
                }
                QuicStreamIdTag tag;
                item.GetTag(tag);
                FeatStat& st = rx[idx][LogicalStream(tag.GetStreamId())];
                for (uint32_t i = item.GetStart(); i < item.GetEnd(); ++i)
                {
                    if (raw[i] != (uint8_t)(st.bytes & 0xff))
                    {
                        corrupt[idx] = true;
                    }
                    st.bytes++;
                }
                st.first = std::min(st.first, Simulator::Now());
                st.last = Simulator::Now();
            }
        }
    }
};

class FeatTransferTest : public TestCase
{
  public:
    FeatTransferTest(std::string name, std::string cc, double uniform, double burst)
        : TestCase(name),
          m_cc(cc),
          m_uniform(uniform),
          m_burst(burst)
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.cc = m_cc;
        r.uniformLoss = m_uniform;
        r.burstStartRate = m_burst;
        r.Build();
        r.Run();
        for (uint32_t sid = 1; sid <= 3; ++sid)
        {
            NS_TEST_ASSERT_MSG_EQ(r.rx[0][sid].bytes,
                                  r.serverBytesPerStream,
                                  "stream " << sid << " complete");
        }
        NS_TEST_ASSERT_MSG_EQ(r.corrupt[0], false, "no corrupted or reordered bytes");
    }

    std::string m_cc;
    double m_uniform;
    double m_burst;
};

class FeatThroughputTest : public TestCase
{
  public:
    FeatThroughputTest()
        : TestCase(
              "throughput: 3 MB over 10 Mbps with 40 ms RTT finishes within 4.5 s of the handshake")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 3000000;
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 3000000u, "all bytes delivered");
        double dur = r.rx[0][1].last.GetSeconds() - 0.1;
        NS_TEST_ASSERT_MSG_LT(dur, 4.5, "transfer took " << dur << " s (ideal 2.4 s)");
    }
};

static uint32_t g_featMaxIpBytes = 0;

static void
FeatRecordIpSend(const Ipv4Header& h, Ptr<const Packet> p, uint32_t)
{
    g_featMaxIpBytes = std::max(g_featMaxIpBytes, p->GetSize() + h.GetSerializedSize());
}

class FeatNoFragmentationTest : public TestCase
{
  public:
    FeatNoFragmentationTest()
        : TestCase("datagrams: data plus the ACK frame never exceed the segment size, so IP never "
                   "fragments")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 3000000;
        r.uniformLoss = 0.01;
        r.Build();
        g_featMaxIpBytes = 0;
        // the server is node 0: everything it sends is data frames with an ACK frame appended
        r.nodes.Get(0)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext(
            "SendOutgoing",
            MakeCallback(&FeatRecordIpSend));
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 3000000u, "all bytes delivered");
        uint32_t seg = DynamicCast<QuicSocketBase>(r.accepted[0])->GetSegSize();
        // segment size plus IPv4 (20), UDP (8) and the short QUIC header (13)
        NS_TEST_ASSERT_MSG_GT(g_featMaxIpBytes, seg, "the server must send (almost) full segments");
        NS_TEST_ASSERT_MSG_LT_OR_EQ(g_featMaxIpBytes,
                                    seg + 41,
                                    "largest IP datagram the server handed to the link, segment "
                                        << seg);
    }
};

class FeatRoundRobinLatencyTest : public TestCase
{
  public:
    FeatRoundRobinLatencyTest(bool rr)
        : TestCase(rr ? "end-to-end: round-robin serves a late small stream while a 2 MB backlog "
                        "is queued"
                      : "end-to-end: stream FIFO makes the small stream wait for the 2 MB backlog"),
          m_rr(rr)
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.maxStreamData = 16777216;
        r.sched = m_rr ? QuicSocketTxRoundRobinScheduler::GetTypeId()
                       : QuicSocketTxStreamFifoScheduler::GetTypeId();
        r.onAccept = [](Ptr<Socket> s) {
            FeatRig::SendPattern(s, ServerStreamId(1), 2000000);
            FeatRig::SendPattern(s, ServerStreamId(2), 1000);
        };
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][2].bytes, 1000u, "small stream delivered");
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 2000000u, "backlog delivered");
        double wait = r.rx[0][2].last.GetSeconds() - 0.1;
        if (m_rr)
        {
            NS_TEST_ASSERT_MSG_LT(wait,
                                  0.5,
                                  "round-robin: small stream done after " << wait << " s");
        }
        else
        {
            NS_TEST_ASSERT_MSG_GT(wait, 1.0, "FIFO: small stream done after " << wait << " s");
        }
    }

    bool m_rr;
};

class FeatHandshakeWriteTest : public TestCase
{
  public:
    FeatHandshakeWriteTest()
        : TestCase(
              "writes issued right after Connect() are queued and delivered after the handshake")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 0;
        uint64_t received = 0;
        bool bad = false;
        r.onClientConnected = [](uint32_t, Ptr<Socket> c) { FeatRig::SendPattern(c, 0, 50000); };
        r.Build();
        Simulator::Schedule(Seconds(0.05), [&r, &received, &bad]() {
            r.listen->SetAcceptCallback(
                MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                MakeBoundCallback(&FeatHandshakeWriteTest::AcceptCount, &received, &bad));
        });
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(received,
                              50000u,
                              "server received all bytes written during the handshake");
        NS_TEST_ASSERT_MSG_EQ(bad, false, "bytes in order");
    }

    static void AcceptCount(uint64_t* received, bool* bad, Ptr<Socket> s, const Address&)
    {
        s->SetRecvCallback(MakeBoundCallback(&FeatHandshakeWriteTest::ServerRead, received, bad));
    }

    static void ServerRead(uint64_t* received, bool* bad, Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            std::vector<uint8_t> raw(p->GetSize());
            p->CopyData(raw.data(), raw.size());
            for (uint8_t b : raw)
            {
                if (b != (uint8_t)(*received & 0xff))
                {
                    *bad = true;
                }
                ++*received;
            }
        }
    }
};

class FeatPendingWriteBoundTest : public TestCase
{
  public:
    FeatPendingWriteBoundTest()
        : TestCase("memory: writes queued before the handshake are bounded")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 0;
        uint64_t accepted = 0;
        bool refused = false;
        r.onAccept = [](Ptr<Socket>) {};
        r.onClientConnected = [&accepted, &refused](uint32_t, Ptr<Socket> c) {
            for (uint32_t i = 0; i < 20000 && !refused; ++i)
            {
                int n = c->Send(Create<Packet>(100000), 0);
                if (n < 0)
                {
                    refused = true;
                }
                else
                {
                    accepted += 100000;
                }
            }
        };
        r.stopAt = Seconds(0.2);
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(refused,
                              true,
                              "Send() must refuse once the pending-write limit is reached");
        NS_TEST_ASSERT_MSG_LT(accepted,
                              1000000000ULL,
                              "bounded to well under 1 GB, accepted " << accepted);
    }
};

class FeatDelayedAckTest : public TestCase
{
  public:
    FeatDelayedAckTest()
        : TestCase("delayed ACK: about one ACK packet per two data packets (msquic tolerance 2)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.queue = "3000p";
        r.serverStreams = 1;
        r.serverBytesPerStream = 3000000;
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 3000000u, "delivered");
        double ratio = (double)r.packetsToServer / (double)r.dataPacketsToClient;
        NS_TEST_ASSERT_MSG_GT(ratio, 0.35, "ACK/data ratio " << ratio);
        NS_TEST_ASSERT_MSG_LT(ratio, 0.65, "ACK/data ratio " << ratio);
    }
};

class FeatCloseTerminatesTest : public TestCase
{
  public:
    FeatCloseTerminatesTest()
        : TestCase(
              "close: after the server closes, both sides go quiet (no CONNECTION_CLOSE ping-pong)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 100000;
        r.stopAt = Seconds(120);
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 100000u, "delivered");
        NS_TEST_ASSERT_MSG_EQ(r.lateTx, 0u, "packets still exchanged after t = 30 s: " << r.lateTx);
    }
};

class FeatConcurrentConnectionsTest : public TestCase
{
  public:
    FeatConcurrentConnectionsTest(std::string name, double spacing)
        : TestCase(name),
          m_spacing(spacing)
    {
    }

    double m_spacing;

  private:
    void DoRun() override
    {
        FeatRig r;
        r.nClients = 4;
        r.clientSpacing = m_spacing;
        r.serverCloses = false;
        r.serverStreams = 2;
        r.serverBytesPerStream = 200000;
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.accepted.size(), 4u, "accepted connections");
        for (uint32_t c = 0; c < 4; ++c)
        {
            for (uint32_t sid = 1; sid <= 2; ++sid)
            {
                NS_TEST_ASSERT_MSG_EQ(r.rx[c][sid].bytes,
                                      200000u,
                                      "client " << c << " stream " << sid);
            }
            NS_TEST_ASSERT_MSG_EQ(r.corrupt[c], false, "client " << c << " data intact");
        }
    }
};

class FeatLossRecoveryOpenTest : public TestCase
{
  public:
    FeatLossRecoveryOpenTest()
        : TestCase("loss recovery: 3% loss, server never closes, every stream still completes")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.uniformLoss = 0.03;
        r.serverCloses = false;
        r.Build();
        r.stopAt = Seconds(60);
        r.Run();
        for (uint32_t sid = 1; sid <= 3; ++sid)
        {
            NS_TEST_ASSERT_MSG_EQ(r.rx[0][sid].bytes, r.serverBytesPerStream, "stream " << sid);
        }
        NS_TEST_ASSERT_MSG_EQ(r.accepted.size(), 1u, "accepted");
    }
};

// Changes attribute defaults for one test case and puts the previous values back afterwards, so
// that a case does not leak its settings into the next one.
uint64_t
FeatDefaultUint(const std::string& type, const std::string& attr)
{
    TypeId::AttributeInformation info;
    NS_ABORT_MSG_UNLESS(TypeId::LookupByName(type).LookupAttributeByName(attr, &info),
                        "no attribute " << attr);
    return std::stoull(info.initialValue->SerializeToString(info.checker));
}

class FeatDefaultsGuard
{
  public:
    void Set(const std::string& type, const std::string& attr, uint64_t value)
    {
        m_saved.push_back(std::make_pair(type + "::" + attr, FeatDefaultUint(type, attr)));
        Config::SetDefault(type + "::" + attr, UintegerValue(value));
    }

    ~FeatDefaultsGuard()
    {
        for (auto it = m_saved.rbegin(); it != m_saved.rend(); ++it)
        {
            Config::SetDefault(it->first, UintegerValue(it->second));
        }
    }

  private:
    std::vector<std::pair<std::string, uint64_t>> m_saved;
};

class FeatSocketBufferWakeupTest : public TestCase
{
  public:
    FeatSocketBufferWakeupTest(std::string name, uint32_t streams, uint64_t bytesPerStream)
        : TestCase(name),
          m_streams(streams),
          m_bytes(bytesPerStream)
    {
    }

  private:
    void DoRun() override
    {
        FeatDefaultsGuard guard;
        guard.Set("ns3::QuicSocketBase", "SocketSndBufSize", 60000);
        // no window update can come for a 2 MB transfer (it takes 4 MiB delivered): only the full
        // socket buffer holds the stream back, and the application has already written everything
        guard.Set("ns3::QuicSocketBase", "MaxStreamData", 16777216);
        guard.Set("ns3::QuicSocketBase", "MaxData", 67108864);
        FeatRig r;
        r.serverCloses = false;
        r.stopAt = Seconds(60);
        // written all at once after the handshake (before it, writes wait in a queue bounded by the
        // socket buffer): the stream buffers take everything, the socket buffer only 60 kB
        const uint32_t streams = m_streams;
        const uint64_t bytes = m_bytes;
        r.onAccept = [streams, bytes](Ptr<Socket> s) {
            for (uint32_t sid = 1; sid <= streams; ++sid)
            {
                Simulator::Schedule(Seconds(1),
                                    &FeatRig::SendPattern,
                                    s,
                                    ServerStreamId(sid),
                                    bytes);
            }
        };
        r.Build();
        r.Run();
        for (uint32_t sid = 1; sid <= m_streams; ++sid)
        {
            NS_TEST_ASSERT_MSG_EQ(r.rx[0][sid].bytes, m_bytes, "stream " << sid << " delivered");
        }
        NS_TEST_ASSERT_MSG_EQ(r.corrupt[0], false, "no corrupted bytes");
    }

    uint32_t m_streams;
    uint64_t m_bytes;
};

class FeatWindowFitsBuffersTest : public TestCase
{
  public:
    FeatWindowFitsBuffersTest(std::string name, uint32_t streamBufSize, uint32_t socketBufSize)
        : TestCase(name),
          m_streamBufSize(streamBufSize),
          m_socketBufSize(socketBufSize)
    {
    }

  private:
    void DoRun() override
    {
        FeatDefaultsGuard guard;
        // the receive buffers are far smaller than the 4 MiB window the receiver advertises
        if (m_streamBufSize > 0)
        {
            guard.Set("ns3::QuicStreamBase", "StreamRcvBufSize", m_streamBufSize);
        }
        if (m_socketBufSize > 0)
        {
            guard.Set("ns3::QuicSocketBase", "SocketRcvBufSize", m_socketBufSize);
        }
        guard.Set("ns3::QuicSocketBase", "MaxStreamData", 4194304);
        guard.Set("ns3::QuicSocketBase", "MaxData", 16777216);
        FeatRig r;
        r.rate = "100Mbps";
        r.uniformLoss = 0.01; // holes: out-of-order data piles up in the stream buffer and is
                              // released when they fill
        r.serverStreams = 1;
        r.serverBytesPerStream = 3000000;
        r.serverCloses = false;
        r.stopAt = Seconds(60);
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 3000000u, "all bytes delivered");
        NS_TEST_ASSERT_MSG_EQ(r.corrupt[0], false, "no corrupted bytes");
    }

    uint32_t m_streamBufSize; //!< 0 keeps the default
    uint32_t m_socketBufSize; //!< 0 keeps the default
};

// A 20 MB bulk transfer over 100 Mbps with light random loss. The window grows past the point where
// the flushes are limited by scheduling, which makes the sender ask the peer to acknowledge only
// every 41st packet; the losses then cut the window down. The tolerance has to follow the window
// down: with a window smaller than the tolerance the peer can only acknowledge on its delayed-ACK
// timer, which stalls the ACK clock.
class FeatAckToleranceTest : public TestCase
{
  public:
    FeatAckToleranceTest()
        : TestCase("ack frequency: the tolerance asked of the peer follows the window, so light "
                   "loss at 100 Mbps is not throttled")
    {
    }

  private:
    // the application writes as the socket has room, like a bulk sender
    void Fill()
    {
        while (m_sent < kTotal)
        {
            uint32_t n = (uint32_t)std::min<uint64_t>(16000, kTotal - m_sent);
            if (m_srv->GetTxAvailable() < n)
            {
                break;
            }
            std::vector<uint8_t> buf(n);
            for (uint32_t i = 0; i < n; ++i)
            {
                buf[i] = (uint8_t)((m_sent + i) & 0xff);
            }
            if (m_srv->Send(Create<Packet>(buf.data(), n), ServerStreamId(1)) < 0)
            {
                break;
            }
            m_sent += n;
        }
        if (m_sent < kTotal)
        {
            Simulator::Schedule(MilliSeconds(2), &FeatAckToleranceTest::Fill, this);
        }
    }

    void DoRun() override
    {
        const uint32_t divisor =
            (uint32_t)FeatDefaultUint("ns3::QuicSocketBase", "AckToleranceCwndDivisor");
        NS_TEST_ASSERT_MSG_GT(divisor, 0u, "the limit is on by default");
        FeatRig r;
        r.rate = "100Mbps";
        r.delay = "10ms";
        r.uniformLoss = 0.001;
        r.stopAt = Seconds(15);
        r.onAccept = [this](Ptr<Socket> s) {
            m_srv = s;
            Fill();
        };
        r.Build();
        uint32_t violations = 0;
        uint32_t maxTolerance = 0;
        std::function<void()> sample = [&]() {
            if (!r.accepted.empty())
            {
                Ptr<QuicSocketBase> s = DynamicCast<QuicSocketBase>(r.accepted[0]);
                uint32_t limit =
                    std::max<uint32_t>(2,
                                       s->GetCongestionWindowBytes() / s->GetSegSize() / divisor);
                maxTolerance = std::max<uint32_t>(maxTolerance, s->GetPeerAckTolerance());
                violations += s->GetPeerAckTolerance() > limit;
            }
            Simulator::Schedule(MilliSeconds(1), sample);
        };
        Simulator::Schedule(Seconds(0.2), sample);
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, kTotal, "all bytes delivered");
        NS_TEST_ASSERT_MSG_EQ(r.corrupt[0], false, "no corrupted bytes");
        NS_TEST_ASSERT_MSG_GT(maxTolerance,
                              2u,
                              "the tolerance is raised at all, otherwise nothing is checked");
        NS_TEST_ASSERT_MSG_EQ(
            violations,
            0u,
            "1 ms samples with the tolerance above the window limit (without the limit: 93%)");
        // measured: 4.6 s with the limit, 6.9 s without it
        double dur = r.rx[0][1].last.GetSeconds() - 0.1;
        NS_TEST_ASSERT_MSG_LT(dur, 5.8, "transfer took " << dur << " s");
    }

    static constexpr uint64_t kTotal = 20000000;
    Ptr<Socket> m_srv;
    uint64_t m_sent{0};
};

// ---------------------------------------------------------------------------
// RFC conformance of the recovery, close and negotiation behaviour
// ---------------------------------------------------------------------------

namespace
{

/**
 * The type of the first frame of a packet handed to the Tx trace (the payload without the packet
 * header), or -1 when it is not a short-header packet: handshake payloads are not frame sequences.
 */
int
FeatFirstFrame(Ptr<const Packet> p, const QuicHeader& h)
{
    if (!h.IsShort() || p->GetSize() == 0)
    {
        return -1;
    }
    Ptr<Packet> c = p->Copy();
    QuicSubheader sub;
    c->RemoveHeader(sub);
    return sub.GetFrameType();
}

Ptr<QuicSocketBase>
FeatQuic(Ptr<Socket> s)
{
    return DynamicCast<QuicSocketBase>(s);
}

} // namespace

/**
 * RFC 9002 s5: an RTT sample subtracts the ack delay (microseconds on the wire) only after the
 * handshake is confirmed, never more than max_ack_delay and never below min_rtt; min_rtt is the
 * smallest raw sample and latest_rtt the raw one.
 */
class FeatRttSampleTest : public TestCase
{
  public:
    FeatRttSampleTest()
        : TestCase("RTT samples: ack delay in microseconds, capped at max_ack_delay, kept above "
                   "min_rtt (RFC 9002 s5)")
    {
    }

  private:
    void Ack(uint32_t pn, Time sent, uint64_t delayUs)
    {
        Ptr<QuicSocketTxItem> item = CreateObject<QuicSocketTxItem>();
        item->m_packet = Create<Packet>(500);
        item->m_packetNumber = SequenceNumber32(pn);
        item->m_lastSent = sent;
        std::vector<uint32_t> gaps, blocks;
        QuicSubheader ack = QuicSubheader::CreateAck(pn, delayUs, pn, gaps, blocks);
        std::vector<Ptr<QuicSocketTxItem>> newAcks = {item};
        m_cc->OnAckReceived(m_tcb, ack, newAcks, nullptr);
    }

    void DoRun() override
    {
        m_tcb = CreateObject<QuicSocketState>();
        m_cc = CreateObject<QuicCongestionOps>();
        m_tcb->m_handshakeConfirmed = true;
        m_tcb->m_maxAckDelay = MilliSeconds(25);
        NS_TEST_ASSERT_MSG_EQ(m_tcb->m_minRtt == Time::Max(),
                              true,
                              "no min_rtt before the first sample");

        // (send times are absolute: an earlier test case may have left the simulation clock past
        // zero)
        Time t0 = Simulator::Now();
        // 50 ms sample without ack delay: srtt = min_rtt = 50 ms
        Simulator::Schedule(MilliSeconds(50), &FeatRttSampleTest::Ack, this, 1, t0, 0);
        // 70 ms sample with 20 ms of ack delay: adjusted to 50 ms, srtt stays 50 ms
        Simulator::Schedule(MilliSeconds(170),
                            &FeatRttSampleTest::Ack,
                            this,
                            2,
                            t0 + MilliSeconds(100),
                            20000);
        Simulator::Schedule(MilliSeconds(171), [this]() { m_srtt1 = m_tcb->m_smoothedRtt; });
        // 100 ms sample with 60 ms of ack delay: the delay counts as 25 ms (max_ack_delay),
        // adjusted to 75 ms
        Simulator::Schedule(MilliSeconds(300),
                            &FeatRttSampleTest::Ack,
                            this,
                            3,
                            t0 + MilliSeconds(200),
                            60000);
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_LT(std::abs((m_srtt1 - MilliSeconds(50)).GetMicroSeconds()),
                              2,
                              "srtt after the second sample: " << m_srtt1);
        // 50 * 7/8 + 75 / 8
        NS_TEST_ASSERT_MSG_LT(
            std::abs((m_tcb->m_smoothedRtt - MicroSeconds(53125)).GetMicroSeconds()),
            2,
            "srtt after the third sample: " << m_tcb->m_smoothedRtt);
        NS_TEST_ASSERT_MSG_EQ(m_tcb->m_minRtt,
                              MilliSeconds(50),
                              "min_rtt is the smallest raw sample");
        NS_TEST_ASSERT_MSG_EQ(m_tcb->m_latestRtt,
                              MilliSeconds(100),
                              "latest_rtt is the raw sample");
    }

    Ptr<QuicSocketState> m_tcb;
    Ptr<QuicCongestionOps> m_cc;
    Time m_srtt1;
};

/**
 * RFC 9002 s6.1.1: a packet is lost once kPacketThreshold (3) packet numbers separate it from an
 * acknowledged one.
 */
class FeatPacketThresholdTest : public TestCase
{
  public:
    FeatPacketThresholdTest()
        : TestCase("loss detection: a packet 3 numbers below the largest acknowledged is lost, 2 "
                   "is not (RFC 9002 s6.1.1)")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<QuicSocketTxBuffer> buf = CreateObject<QuicSocketTxBuffer>();
        buf->SetMaxBufferSize(1 << 20);
        buf->SetScheduler(CreateObject<QuicSocketTxStreamFifoScheduler>());
        Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState>();
        for (uint32_t pn = 1; pn <= 8; ++pn)
        {
            Ptr<Packet> p = Create<Packet>(0);
            p->AddHeader(QuicSubheader::CreatePing());
            buf->Add(p);
            buf->NextStream0Sequence(SequenceNumber32(pn));
        }
        buf->SetAckFloor(5);
        std::vector<uint32_t> blocks, gaps;
        buf->OnAckUpdate(tcb, 5, blocks, gaps);
        std::set<uint32_t> lost;
        for (auto& item : buf->DetectLostPackets())
        {
            lost.insert(item->m_packetNumber.GetValue());
        }
        NS_TEST_ASSERT_MSG_EQ(lost.count(1), 1u, "packet 1 (4 below the largest) must be lost");
        NS_TEST_ASSERT_MSG_EQ(lost.count(2), 1u, "packet 2 (3 below the largest) must be lost");
        NS_TEST_ASSERT_MSG_EQ(lost.count(3),
                              0u,
                              "packet 3 (2 below the largest) is only reordered");
        NS_TEST_ASSERT_MSG_EQ(lost.count(6),
                              0u,
                              "packets above the largest acknowledged are never lost");
        Simulator::Destroy();
    }
};

/**
 * RFC 9000 s19.3: the ack delay is sent in microseconds divided by 2^ack_delay_exponent (3 by
 * default).
 */
class FeatAckDelayExponentTest : public TestCase
{
  public:
    FeatAckDelayExponentTest()
        : TestCase(
              "ACK frames carry the ack delay divided by 2^ack_delay_exponent (RFC 9000 s19.3)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 500;
        r.serverCloses = false;
        r.stopAt = Seconds(2);
        r.Build();
        r.onClientConnected = [this](uint32_t, Ptr<Socket> c) {
            FeatQuic(c)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatAckDelayExponentTest::OnTx, this));
        };
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 500u, "delivered");
        NS_TEST_ASSERT_MSG_GT(m_acks, 0u, "no ACK seen");
        // the single data packet is acknowledged after the 25 ms delayed-ACK timer: 25000 / 8 =
        // 3125 on the wire
        NS_TEST_ASSERT_MSG_GT(m_maxDelay,
                              1000u,
                              "no delayed ACK seen, largest ack delay field " << m_maxDelay);
        NS_TEST_ASSERT_MSG_LT(m_maxDelay,
                              3300u,
                              "ack delay field " << m_maxDelay << " is not scaled by the exponent");
    }

    void OnTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (h.IsShort() && p->GetSize() > 0)
        {
            Ptr<Packet> c = p->Copy();
            QuicSubheader sub;
            c->RemoveHeader(sub);
            if (sub.GetFrameType() == QuicSubheader::ACK)
            {
                ++m_acks;
                m_maxDelay = std::max<uint64_t>(m_maxDelay, sub.GetAckDelay());
            }
        }
    }

    uint32_t m_acks{0};
    uint64_t m_maxDelay{0};
};

/**
 * Server-side recorder shared by the two PTO tests: the first data packet, the first PING that is
 * not a path MTU probe, and the first data packet sent again after a quiet spell.
 */
class FeatPtoRecorder
{
  public:
    void OnServerTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        int first = FeatFirstFrame(p, h);
        if (first < 0)
        {
            return;
        }
        // (a PING padded to the probe size is a path MTU probe, not a PTO probe)
        if (first == QuicSubheader::PING && p->GetSize() < 100)
        {
            if (pings++ == 0)
            {
                firstPing = Simulator::Now();
            }
        }
        else if (first >= QuicSubheader::STREAM && first <= QuicSubheader::STREAM_OFF_LEN_FIN)
        {
            if (firstData.IsZero())
            {
                firstData = Simulator::Now();
            }
            else if (secondData.IsZero() && Simulator::Now() > firstData + MilliSeconds(50))
            {
                secondData = Simulator::Now();
            }
        }
    }

    uint32_t pings{0};
    Time firstPing;
    Time firstData;
    Time secondData;
};

/**
 * RFC 9002 s6.2.2: before any RTT sample the first PTO is smoothed_rtt (kInitialRtt, 333 ms) + 4 *
 * rttvar (2 * kInitialRtt) + max_ack_delay (25 ms), about 1.02 s, measured from the packet that was
 * sent.
 */
class FeatInitialPtoTest : public TestCase
{
  public:
    FeatInitialPtoTest()
        : TestCase("PTO: the first one, before any RTT sample, is 3 * kInitialRtt + max_ack_delay "
                   "after the packet (RFC 9002 s6.2.2)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 500;
        r.serverCloses = false;
        r.stopAt = Seconds(4);
        r.onAccept = [this](Ptr<Socket> s) {
            FeatQuic(s)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatPtoRecorder::OnServerTx, &m_rec));
            FeatRig::SendPattern(s, ServerStreamId(1), 500);
        };
        r.Build();
        // nothing the client sends after the handshake reaches the server: its ACKs never arrive
        Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
        em->SetAttribute("ErrorRate", DoubleValue(1.0));
        em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        em->Disable();
        r.dev.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        Simulator::Schedule(MilliSeconds(175), &ErrorModel::Enable, em);
        Simulator::Schedule(Seconds(2.5), &ErrorModel::Disable, em);
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 500u, "delivered");
        NS_TEST_ASSERT_MSG_EQ(m_rec.secondData.IsStrictlyPositive(),
                              true,
                              "the data was never sent again");
        Time pto = m_rec.secondData - m_rec.firstData;
        NS_TEST_ASSERT_MSG_GT(pto, Seconds(0.99), "first PTO after " << pto.GetSeconds() << " s");
        NS_TEST_ASSERT_MSG_LT(pto, Seconds(1.1), "first PTO after " << pto.GetSeconds() << " s");
    }

    FeatPtoRecorder m_rec;
};

/**
 * RFC 9002 s6.2.4: a probe timeout with one packet outstanding and nothing new to send repeats the
 * packet and sends a PING as the second probe (an empty packet would not be ack-eliciting).
 */
class FeatPtoPingTest : public TestCase
{
  public:
    FeatPtoPingTest()
        : TestCase(
              "PTO: the second probe is a PING when nothing else is outstanding (RFC 9002 s6.2.4)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 500;
        r.serverCloses = false;
        r.stopAt = Seconds(4);
        r.onAccept = [this](Ptr<Socket> s) {
            FeatQuic(s)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatPtoRecorder::OnServerTx, &m_rec));
            FeatRig::SendPattern(s, ServerStreamId(1), 500);
            // one more packet once the connection is quiet and everything is acknowledged
            Simulator::Schedule(Seconds(0.6),
                                [s]() { s->Send(Create<Packet>(500), ServerStreamId(1)); });
        };
        r.Build();
        // the ACK for that last packet never arrives
        Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
        em->SetAttribute("ErrorRate", DoubleValue(1.0));
        em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        em->Disable();
        r.dev.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        Simulator::Schedule(Seconds(0.55), &ErrorModel::Enable, em);
        Simulator::Schedule(Seconds(2.5), &ErrorModel::Disable, em);
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 1000u, "delivered");
        NS_TEST_ASSERT_MSG_GT(m_rec.pings, 0u, "the PTO never sent a PING");
        NS_TEST_ASSERT_MSG_GT(m_rec.firstPing,
                              Seconds(0.6),
                              "the PING came before the last packet was sent");
    }

    FeatPtoRecorder m_rec;
};

/**
 * RFC 9000 s17.4: the server reflects the spin value and the client sends the opposite, so the bit
 * flips about once per round trip.
 */
class FeatSpinBitTest : public TestCase
{
  public:
    FeatSpinBitTest()
        : TestCase("spin bit: the client inverts the value it receives, so the bit flips every "
                   "round trip (RFC 9000 s17.4)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 1000000;
        r.onClientConnected = [this](uint32_t, Ptr<Socket> c) {
            FeatQuic(c)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatSpinBitTest::OnClientTx, this));
        };
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 1000000u, "delivered");
        NS_TEST_ASSERT_MSG_GT(m_flips,
                              4u,
                              "the client's spin bit flipped only " << m_flips << " times");
    }

    void OnClientTx(Ptr<const Packet>, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (h.IsShort())
        {
            bool bit = h.GetSpinBit();
            if (m_seen && bit != m_last)
            {
                ++m_flips;
            }
            m_last = bit;
            m_seen = true;
        }
    }

    bool m_seen{false};
    bool m_last{false};
    uint32_t m_flips{0};
};

/**
 * RFC 9000 s10.1: max_idle_timeout 0 means no limit for that endpoint; the connection then lives as
 * long as the other endpoint's limit allows, and not at all when both are 0.
 */
class FeatIdleTimeoutTest : public TestCase
{
  public:
    FeatIdleTimeoutTest(std::string name, double clientIdle, double serverIdle)
        : TestCase(name),
          m_clientIdle(clientIdle),
          m_serverIdle(serverIdle)
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 200000;
        r.serverCloses = false;
        r.stopAt = Seconds(200);
        r.Build();
        r.listen->SetAttribute("IdleTimeout", TimeValue(Seconds(m_serverIdle)));
        r.clients[0]->SetAttribute("IdleTimeout", TimeValue(Seconds(m_clientIdle)));
        Simulator::Schedule(Seconds(3), [this, &r]() {
            m_openAt3 = FeatQuic(r.clients[0])->GetSocketState() == QuicSocketBase::OPEN;
        });
        Simulator::Schedule(Seconds(150), [this, &r]() {
            m_openAt150 = FeatQuic(r.clients[0])->GetSocketState() == QuicSocketBase::OPEN;
        });
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 200000u, "delivered");
        NS_TEST_ASSERT_MSG_EQ(m_openAt3,
                              true,
                              "the connection was closed during the first seconds");
        bool limited = m_clientIdle > 0 || m_serverIdle > 0;
        NS_TEST_ASSERT_MSG_EQ(m_openAt150,
                              !limited,
                              "the idle timeout "
                                  << (limited ? "never fired"
                                              : "fired although it is disabled on both sides"));
    }

    double m_clientIdle;
    double m_serverIdle;
    bool m_openAt3{false};
    bool m_openAt150{false};
};

/**
 * RFC 9000 s10.2.2: after a CONNECTION_CLOSE the endpoint drains for at least three PTOs: the
 * application is told at once, the connection state stays for a while and then goes.
 */
class FeatDrainingTest : public TestCase
{
  public:
    FeatDrainingTest()
        : TestCase("draining: a CONNECTION_CLOSE from the peer notifies at once and keeps the "
                   "state for three PTOs (RFC 9000 s10.2.2)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 100000;
        r.Build();
        r.clients[0]->SetCloseCallbacks(MakeCallback(&FeatDrainingTest::Closed, this),
                                        MakeCallback(&FeatDrainingTest::Closed, this));
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 100000u, "delivered");
        NS_TEST_ASSERT_MSG_EQ(m_closedAt.IsStrictlyPositive(),
                              true,
                              "the application was never told of the close");
        NS_TEST_ASSERT_MSG_EQ(m_drainingAfter20ms,
                              true,
                              "the connection state was dropped at once instead of draining");
        NS_TEST_ASSERT_MSG_EQ(m_goneAfter5s, true, "the connection never left the draining state");
    }

    void Closed(Ptr<Socket> s)
    {
        if (m_closedAt.IsZero())
        {
            m_closedAt = Simulator::Now();
            Simulator::Schedule(MilliSeconds(20), [this, s]() {
                m_drainingAfter20ms = FeatQuic(s)->GetSocketState() == QuicSocketBase::CLOSING;
            });
            Simulator::Schedule(Seconds(5), [this, s]() {
                m_goneAfter5s = FeatQuic(s)->GetSocketState() == QuicSocketBase::IDLE;
            });
        }
    }

    Time m_closedAt;
    bool m_drainingAfter20ms{false};
    bool m_goneAfter5s{false};
};

/**
 * RFC 9000 s13.3: HANDSHAKE_DONE is retransmitted when its packet is lost.
 */
class FeatHandshakeDoneRetransmitTest : public TestCase
{
  public:
    FeatHandshakeDoneRetransmitTest()
        : TestCase("HANDSHAKE_DONE is sent again when its packet is lost (RFC 9000 s13.3)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 20000;
        r.serverCloses = false;
        r.stopAt = Seconds(5);
        r.onAccept = [this](Ptr<Socket> s) {
            FeatQuic(s)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatHandshakeDoneRetransmitTest::OnServerTx, this));
            FeatRig::SendPattern(s, ServerStreamId(1), 20000);
        };
        r.Build();
        m_em = CreateObject<RateErrorModel>();
        m_em->SetAttribute("ErrorRate", DoubleValue(1.0));
        m_em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        m_em->Disable();
        r.dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(m_em));
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 20000u, "delivered");
        NS_TEST_ASSERT_MSG_GT(m_handshakeDone,
                              1u,
                              "HANDSHAKE_DONE was sent " << m_handshakeDone << " time(s)");
    }

    void OnServerTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (FeatFirstFrame(p, h) == QuicSubheader::HANDSHAKE_DONE)
        {
            if (m_handshakeDone++ == 0)
            {
                // the first one never reaches the client
                m_em->Enable();
                Simulator::Schedule(MilliSeconds(30), &ErrorModel::Disable, m_em);
            }
        }
    }

    Ptr<RateErrorModel> m_em;
    uint32_t m_handshakeDone{0};
};

/**
 * RFC 9000 s10.2.1: an endpoint that closed the connection answers the packets it still receives
 * with CONNECTION_CLOSE. The first CONNECTION_CLOSE is lost here, and the client sends a packet
 * while the closing period (three PTOs) lasts; without the repeat the peer learns of the close only
 * when its idle timer expires.
 */
class FeatClosingRepeatTest : public TestCase
{
  public:
    FeatClosingRepeatTest()
        : TestCase("a lost CONNECTION_CLOSE is repeated to the peer's packets (RFC 9000 s10.2.1)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 20000;
        r.serverCloses = true;
        r.stopAt = Seconds(8);
        r.onAccept = [this](Ptr<Socket> s) {
            FeatQuic(s)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatClosingRepeatTest::OnServerTx, this));
            FeatRig::SendPattern(s, ServerStreamId(1), 20000);
            s->Close();
        };
        r.Build();
        m_client = r.clients[0];
        r.clients[0]->SetCloseCallbacks(MakeCallback(&FeatClosingRepeatTest::OnClientClosed, this),
                                        MakeCallback(&FeatClosingRepeatTest::OnClientClosed, this));
        m_em = CreateObject<RateErrorModel>();
        m_em->SetAttribute("ErrorRate", DoubleValue(1.0));
        m_em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        m_em->Disable();
        r.dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(m_em));
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 20000u, "delivered");
        NS_TEST_ASSERT_MSG_GT(m_closeSent,
                              1u,
                              "CONNECTION_CLOSE was sent " << m_closeSent << " time(s)");
        NS_TEST_ASSERT_MSG_EQ(m_closed, true, "the client learned of the close");
        NS_TEST_ASSERT_MSG_LT(m_closedAt.GetSeconds(),
                              3.0,
                              "the client learned of the close at " << m_closedAt.GetSeconds()
                                                                    << " s");
    }

    void OnServerTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (FeatFirstFrame(p, h) == QuicSubheader::CONNECTION_CLOSE)
        {
            if (m_closeSent++ == 0)
            {
                // the first one never reaches the client
                m_em->Enable();
                Simulator::Schedule(MilliSeconds(30), &ErrorModel::Disable, m_em);
                // the client writes once the loss is over, inside the closing period (at least
                // 75 ms with the default max_ack_delay)
                Simulator::Schedule(MilliSeconds(40), &FeatRig::SendPattern, m_client, 0, 100);
            }
        }
    }

    void OnClientClosed(Ptr<Socket>)
    {
        m_closed = true;
        m_closedAt = Simulator::Now();
    }

    Ptr<RateErrorModel> m_em;
    Ptr<Socket> m_client;
    uint32_t m_closeSent{0};
    bool m_closed{false};
    Time m_closedAt{Seconds(0)};
};

/**
 * Drops the packet at a given arrival index; the index is chosen while the packet is still on the
 * wire, so a test can aim at a packet it saw leave the sender
 */
class FeatDropNth : public ErrorModel
{
  public:
    static TypeId GetTypeId(void)
    {
        static TypeId tid =
            TypeId("FeatDropNth").SetParent<ErrorModel>().AddConstructor<FeatDropNth>();
        return tid;
    }

    uint32_t m_seen{0};
    int64_t m_target{-1};

  private:
    bool DoCorrupt(Ptr<Packet>) override
    {
        return (int64_t)m_seen++ == m_target;
    }

    void DoReset(void) override
    {
    }
};

/**
 * RFC 9001 s4.9.2: the Handshake packet that completes the server's handshake is sent again until
 * HANDSHAKE_DONE arrives. A server that is still connecting drops every 1-RTT packet, so a lost
 * Handshake packet used to leave the connection stuck for good.
 */
class FeatClientHandshakeLossTest : public TestCase
{
  public:
    FeatClientHandshakeLossTest()
        : TestCase("a lost client Handshake packet is sent again (RFC 9001 s4.9.2)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 20000;
        r.serverCloses = false;
        r.stopAt = Seconds(10);
        r.onClientConnected = [this](uint32_t, Ptr<Socket> c) {
            FeatQuic(c)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatClientHandshakeLossTest::OnClientTx, this));
        };
        r.Build();
        m_drop = CreateObject<FeatDropNth>();
        r.dev.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(m_drop));
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(m_dropped, true, "the client sent a Handshake packet");
        NS_TEST_ASSERT_MSG_GT(m_handshakePackets, 1u, "the Handshake packet was sent again");
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 20000u, "the transfer completes");
    }

    void OnClientTx(Ptr<const Packet>, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (h.IsHandshake())
        {
            ++m_handshakePackets;
            if (!m_dropped)
            {
                // the server device counts arrivals in the order the client sent them
                m_dropped = true;
                m_drop->m_target = m_sent;
            }
        }
        ++m_sent;
    }

    Ptr<FeatDropNth> m_drop;
    bool m_dropped{false};
    uint32_t m_sent{0};
    uint32_t m_handshakePackets{0};
};

/**
 * RFC 9000 s7.4.1 and s4.6: a client that connects again to a server it knows sends 0-RTT data
 * within the limits the server announced the last time. The second connection of this test writes
 * at the instant it connects and has to deliver its data both ways, much sooner than a full
 * handshake would allow; with the first packet lost, the packets that follow must still be 0-RTT
 * packets, because the server only learns of the connection from one of them.
 */
class FeatZeroRttTest : public TestCase
{
  public:
    FeatZeroRttTest(bool dropFirst)
        : TestCase(dropFirst
                       ? "0-RTT: the connection is made even when the first packet is lost (RFC "
                         "9000 s7.4.1)"
                       : "0-RTT: data goes both ways from the first flight (RFC 9000 s7.4.1)"),
          m_dropFirst(dropFirst)
    {
    }

  private:
    static constexpr uint64_t kClientBytes = 5000;
    static constexpr uint64_t kServerBytes = 20000;

    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 0;
        r.serverCloses = false;
        r.stopAt = Seconds(60);
        r.onAccept = [this](Ptr<Socket> s) {
            s->SetRecvCallback(MakeCallback(&FeatZeroRttTest::ServerRead, this));
            if (m_second)
            {
                FeatRig::SendPattern(s, ServerStreamId(1), kServerBytes);
            }
        };
        r.Build();
        m_drop = CreateObject<FeatDropNth>();
        r.dev.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(m_drop));
        Ptr<Socket> second;
        // the first connection moves no data and is closed: the client now knows the server and the
        // server the client
        Simulator::Schedule(Seconds(2), [&r]() { r.clients[0]->Close(); });
        Simulator::Schedule(Seconds(40), [this, &r, &second]() {
            m_second = true;
            r.nodes.Get(1)->GetObject<QuicL4Protocol>()->SetAttribute("0RTT-Handshake",
                                                                      BooleanValue(true));
            r.nodes.Get(0)->GetObject<QuicL4Protocol>()->SetAttribute("0RTT-Handshake",
                                                                      BooleanValue(true));
            second = Socket::CreateSocket(r.nodes.Get(1), QuicSocketFactory::GetTypeId());
            second->SetRecvCallback(MakeCallback(&FeatZeroRttTest::ClientRead, this));
            if (m_dropFirst)
            {
                m_drop->m_target = m_drop->m_seen;
            }
            m_start = Simulator::Now();
            second->Connect(InetSocketAddress(r.serverAddr, 4433));
            FeatRig::SendPattern(second, 0, kClientBytes);
        });
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(m_serverRx,
                              kClientBytes,
                              "the client's 0-RTT data reached the server");
        NS_TEST_ASSERT_MSG_EQ(m_clientRx, kServerBytes, "the server's data reached the client");
        if (!m_dropFirst)
        {
            // one way is 20 ms: a full handshake delivers nothing before 60 ms, 0-RTT data arrives
            // after about 20 ms
            NS_TEST_ASSERT_MSG_LT((m_firstServerRx - m_start).GetMilliSeconds(),
                                  50,
                                  "the first data reached the server at "
                                      << (m_firstServerRx - m_start).GetMilliSeconds() << " ms");
        }
    }

    void ServerRead(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            if (m_second)
            {
                if (m_serverRx == 0)
                {
                    m_firstServerRx = Simulator::Now();
                }
                m_serverRx += p->GetSize();
            }
        }
    }

    void ClientRead(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            m_clientRx += p->GetSize();
        }
    }

    bool m_dropFirst;
    bool m_second{false};
    Ptr<FeatDropNth> m_drop;
    Time m_start{Seconds(0)};
    Time m_firstServerRx{Seconds(0)};
    uint64_t m_serverRx{0};
    uint64_t m_clientRx{0};
};

/**
 * Close() on a connection that has nothing to send or to wait for used to do nothing until the idle
 * timeout (30 s) closed the peer: no packet was left to bring the close along. The CONNECTION_CLOSE
 * now goes out at once.
 */
class FeatIdleCloseTest : public TestCase
{
  public:
    FeatIdleCloseTest()
        : TestCase("Close() on an idle connection reaches the peer at once")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 0;
        r.serverCloses = false;
        r.stopAt = Seconds(12);
        r.Build();
        Simulator::Schedule(Seconds(2), [&r]() { r.clients[0]->Close(); });
        Simulator::Schedule(Seconds(2.001), [this, &r]() {
            m_clientEarly = DynamicCast<QuicSocketBase>(r.clients[0])->GetSocketState();
        });
        Simulator::Schedule(Seconds(11), [this, &r]() {
            m_clientState = DynamicCast<QuicSocketBase>(r.clients[0])->GetSocketState();
            m_serverState = DynamicCast<QuicSocketBase>(r.accepted[0])->GetSocketState();
        });
        r.Run();
        // the closing endpoint stays in its closing period (three PTOs, at least 75 ms with the
        // default max_ack_delay), the peer is closed at once
        NS_TEST_ASSERT_MSG_EQ((int)m_clientEarly,
                              (int)QuicSocket::CLOSING,
                              "the closing endpoint is closing right after Close()");
        NS_TEST_ASSERT_MSG_EQ((int)m_clientState,
                              (int)QuicSocket::IDLE,
                              "the closing period ended long before 9 s");
        NS_TEST_ASSERT_MSG_EQ((int)m_serverState, (int)QuicSocket::IDLE, "the peer is closed");
    }

    QuicSocket::QuicStates_t m_clientEarly{QuicSocket::OPEN};
    QuicSocket::QuicStates_t m_clientState{QuicSocket::OPEN};
    QuicSocket::QuicStates_t m_serverState{QuicSocket::OPEN};
};

/**
 * BBR on a link without loss. Every ten seconds it goes through ProbeRTT, with a window of four
 * segments, and has to come out of it at the rate it had. It did not: the minimum window was four
 * segments of the size at the start of the connection, fewer bytes than ProbeRTT leaves in flight
 * once the path MTU discovery has grown the segment, so the pipe never looked drained and the
 * connection stayed at four segments for good (about 10 % of the link). Besides, the rate BBR sets
 * was not the rate the socket paced at, so BBR stayed in Drain and never cycled its gains.
 */
class FeatBbrProbeRttTest : public TestCase
{
  public:
    FeatBbrProbeRttTest()
        : TestCase("BBR: the connection keeps its rate through ProbeRTT (draft-cardwell-iccrg-bbr)")
    {
    }

  private:
    static constexpr uint64_t kTotal = 20000000; //!< 16 s at 10 Mbps

    void Fill()
    {
        while (m_sent < kTotal)
        {
            uint32_t n = (uint32_t)std::min<uint64_t>(16000, kTotal - m_sent);
            if (m_srv->GetTxAvailable() < n ||
                m_srv->Send(Create<Packet>(n), ServerStreamId(1)) < 0)
            {
                break;
            }
            m_sent += n;
        }
        if (m_sent < kTotal)
        {
            Simulator::Schedule(MilliSeconds(2), &FeatBbrProbeRttTest::Fill, this);
        }
    }

    void DoRun() override
    {
        FeatRig r;
        r.cc = "ns3::QuicBbr";
        r.stopAt = Seconds(60);
        r.onAccept = [this](Ptr<Socket> s) {
            m_srv = s;
            Fill();
        };
        r.Build();
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, kTotal, "delivered");
        double dur = r.rx[0][1].last.GetSeconds() - 0.1;
        // 16 s at the link rate; stuck at four segments after the ProbeRTT at 10 s it took several
        // minutes
        NS_TEST_ASSERT_MSG_LT(dur, 20.0, "20 MB over 10 Mbps took " << dur << " s");
    }

    Ptr<Socket> m_srv;
    uint64_t m_sent{0};
};

/**
 * RFC 9000 s6, s17.2.1: the Version Negotiation packet lists the versions in network byte order,
 * and a client that proposed an unknown version carries on with one of them.
 */
class FeatVersionNegotiationTest : public TestCase
{
  public:
    FeatVersionNegotiationTest()
        : TestCase("version negotiation: versions in network byte order, the client retries with a "
                   "supported one (RFC 9000 s6)")
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 50000;
        r.serverCloses = false;
        r.stopAt = Seconds(5);
        r.onAccept = [this](Ptr<Socket> s) {
            FeatQuic(s)->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&FeatVersionNegotiationTest::OnServerTx, this));
            FeatRig::SendPattern(s, ServerStreamId(1), 50000);
        };
        r.Build();
        r.clients[0]->SetAttribute("InitialVersion", UintegerValue(0x2a3a4a5a));
        r.Run();
        NS_TEST_ASSERT_MSG_EQ(m_vnSeen, true, "the server never sent a Version Negotiation packet");
        NS_TEST_ASSERT_MSG_EQ(m_firstVersion,
                              (uint32_t)QUIC_VERSION,
                              "first listed version (network byte order)");
        NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes,
                              50000u,
                              "the client did not carry on with a supported version");
    }

    void OnServerTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (h.IsVersionNegotiation() && !m_vnSeen && p->GetSize() >= 4)
        {
            m_vnSeen = true;
            uint8_t b[4];
            p->CopyData(b, 4);
            m_firstVersion =
                ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        }
    }

    bool m_vnSeen{false};
    uint32_t m_firstVersion{0};
};

/**
 * RFC 9000 s18.2: a transport parameter out of range is a TRANSPORT_PARAMETER_ERROR; 20 is the
 * largest ack_delay_exponent.
 */
class FeatTransportParameterRangeTest : public TestCase
{
  public:
    FeatTransportParameterRangeTest(uint32_t exponent, bool accepted)
        : TestCase("transport parameters: ack_delay_exponent " + std::to_string(exponent) +
                   (accepted ? " is accepted" : " is rejected (RFC 9000 s18.2)")),
          m_exponent(exponent),
          m_accepted(accepted)
    {
    }

  private:
    void DoRun() override
    {
        FeatRig r;
        r.serverStreams = 1;
        r.serverBytesPerStream = 50000;
        r.serverCloses = false;
        r.stopAt = Seconds(5);
        r.Build();
        r.clients[0]->SetAttribute("AckDelayExponent", UintegerValue(m_exponent));
        r.Run();
        if (m_accepted)
        {
            NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes, 50000u, "a valid exponent was refused");
        }
        else
        {
            NS_TEST_ASSERT_MSG_EQ(r.rx[0][1].bytes,
                                  0u,
                                  "the connection went on with an invalid exponent");
        }
    }

    uint32_t m_exponent;
    bool m_accepted;
};

class QuicFeaturesTestSuite : public TestSuite
{
  public:
    QuicFeaturesTestSuite()
        : TestSuite("quic-features", Type::UNIT)
    {
        AddTestCase(new FeatAckFrequencyWireTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatConnectionIdWireTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatControlFramesWireTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatAckRangesWireTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatRfcWireBytesTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatHeaderWireTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatTransportParametersTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatCongestionDefaultsTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatSchedulerConservationTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatSchedulerDataLessFrameTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatRoundRobinFairnessTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatStreamFifoUnfairnessTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatTransferTest("end-to-end: CUBIC, no loss", "ns3::QuicCubic", 0, 0),
                    TestCase::Duration::QUICK);
        AddTestCase(
            new FeatTransferTest("end-to-end: CUBIC, 3% uniform loss", "ns3::QuicCubic", 0.03, 0),
            TestCase::Duration::QUICK);
        AddTestCase(
            new FeatTransferTest("end-to-end: CUBIC, burst loss", "ns3::QuicCubic", 0, 0.005),
            TestCase::Duration::QUICK);
        AddTestCase(new FeatTransferTest("end-to-end: BBR, no loss", "ns3::QuicBbr", 0, 0),
                    TestCase::Duration::QUICK);
        AddTestCase(
            new FeatTransferTest("end-to-end: BBR, 2% uniform loss", "ns3::QuicBbr", 0.02, 0),
            TestCase::Duration::QUICK);
        AddTestCase(new FeatTransferTest("end-to-end: NewReno, 2% uniform loss",
                                         "ns3::QuicCongestionControl",
                                         0.02,
                                         0),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatTransferTest("end-to-end: NewReno, burst loss",
                                         "ns3::QuicCongestionControl",
                                         0,
                                         0.005),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatThroughputTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatNoFragmentationTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatRoundRobinLatencyTest(true), TestCase::Duration::QUICK);
        AddTestCase(new FeatRoundRobinLatencyTest(false), TestCase::Duration::QUICK);
        AddTestCase(new FeatHandshakeWriteTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatPendingWriteBoundTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatDelayedAckTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatCloseTerminatesTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatConcurrentConnectionsTest(
                        "four connections one after another to one listener complete",
                        0.5),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatConcurrentConnectionsTest(
                        "four connections starting together on one listener complete",
                        0.01),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatLossRecoveryOpenTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatSocketBufferWakeupTest("send path: stream data held back by a full "
                                                   "socket buffer is sent once the buffer drains",
                                                   1,
                                                   2000000),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatSocketBufferWakeupTest(
                        "send path: three streams held back by one full socket buffer all complete",
                        3,
                        700000),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatWindowFitsBuffersTest("flow control: a stream buffer smaller than the "
                                                  "advertised window is never overflowed",
                                                  16384,
                                                  0),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatWindowFitsBuffersTest("flow control: a socket buffer smaller than the "
                                                  "advertised window never drops acknowledged data",
                                                  0,
                                                  16384),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatAckToleranceTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatRttSampleTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatPacketThresholdTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatAckDelayExponentTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatInitialPtoTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatPtoPingTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatSpinBitTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatIdleTimeoutTest("idle timeout: 0 on the client leaves the server's "
                                            "limit in charge (RFC 9000 s10.1)",
                                            0,
                                            5),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatIdleTimeoutTest(
                        "idle timeout: 0 on both sides disables the timer (RFC 9000 s10.1)",
                        0,
                        0),
                    TestCase::Duration::QUICK);
        AddTestCase(new FeatDrainingTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatHandshakeDoneRetransmitTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatClientHandshakeLossTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatClosingRepeatTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatBbrProbeRttTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatIdleCloseTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatZeroRttTest(false), TestCase::Duration::QUICK);
        AddTestCase(new FeatZeroRttTest(true), TestCase::Duration::QUICK);
        AddTestCase(new FeatVersionNegotiationTest, TestCase::Duration::QUICK);
        AddTestCase(new FeatTransportParameterRangeTest(20, true), TestCase::Duration::QUICK);
        AddTestCase(new FeatTransportParameterRangeTest(25, false), TestCase::Duration::QUICK);
    }
};

static QuicFeaturesTestSuite sQuicFeaturesTestSuite;
