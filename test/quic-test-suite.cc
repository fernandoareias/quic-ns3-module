/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * QUIC ns-3 module — Test Suite
 *
 * Covers:
 *   - RFC 9000 §19  Frame type wire values (TypeFrame_t)
 *   - RFC 9000 §20  Transport error code values (TransportErrorCodes_t)
 *   - RFC 9000 §19  STREAM frame bit encoding (base 0x08)
 *   - RFC 9000 §19  IsStream() range (0x08–0x0f)
 *   - RFC 9000 §19  Backward-compatibility aliases
 *   - RFC 9000 §20  Backward-compatibility aliases (error codes)
 *   - RFC 9002 §5.3 kInitialRtt = 333 ms
 *   - RFC 9002 §7.6.3 kPersistentCongestionThreshold = 3
 *   - RFC 9002 §7.6.3 Persistent congestion detection in OnPacketsLost()
 *   - RFC 9000 §17.3.1 Spin Bit serialize/deserialize
 *   - RFC 9000 §18.2 active_connection_id_limit ≥ 2
 *   - RFC 9000 §18.2 Stateless Reset Token round-trip
 *   - RFC 9000 §20 FRAME_ENCODING_ERROR wire value
 */

#include "../helper/quic-helper.h"
#include "../model/quic-congestion-ops.h"
#include "../model/quic-cubic.h"
#include "../model/quic-l4-protocol.h"
#include "../model/quic-l5-protocol.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-socket-factory.h"
#include "../model/quic-socket-tx-buffer.h"
#include "../model/quic-socket-tx-roundrobin-scheduler.h"
#include "../model/quic-socket-tx-streamfifo-scheduler.h"
#include "../model/quic-stream-base.h"
#include "../model/quic-stream-id-tag.h"
#include "../model/quic-subheader.h"

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/nstime.h"
#include "ns3/point-to-point-module.h"
#include "ns3/simulator.h"
#include "ns3/test.h"

#include <map>

using namespace ns3;

// ---------------------------------------------------------------------------
// §1  RFC 9000 §19 — Frame type wire values
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que todos os TypeFrame_t têm os valores wire definidos pela RFC 9000 §19.
 */
/** The tests open streams the way an application does: the server writes on its own bidirectional
 * streams. */
static uint64_t
ServerStreamId(uint32_t n)
{
    return 4 * (n - 1) + 1;
} //!< n-th server-initiated bidirectional stream

static uint32_t
LogicalStream(uint64_t id)
{
    return (uint32_t)(id >> 2) + 1;
}

static void
StreamDefaults(void)
{
    // msquic accepts no peer stream until the application allows some (PeerBidiStreamCount)
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(8));
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdUni", UintegerValue(8));
}

class QuicFrameTypeValuesTestCase : public TestCase
{
  public:
    QuicFrameTypeValuesTestCase()
        : TestCase("RFC 9000 §19 — frame type wire values match spec")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::PADDING, 0x00, "PADDING");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::PING, 0x01, "PING");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::ACK, 0x02, "ACK");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::ACK_ECN, 0x03, "ACK_ECN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::RESET_STREAM, 0x04, "RESET_STREAM");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STOP_SENDING, 0x05, "STOP_SENDING");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CRYPTO, 0x06, "CRYPTO");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::NEW_TOKEN, 0x07, "NEW_TOKEN");

        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM, 0x08, "STREAM");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_FIN, 0x09, "STREAM_FIN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_LEN, 0x0a, "STREAM_LEN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_LEN_FIN, 0x0b, "STREAM_LEN_FIN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_OFF, 0x0c, "STREAM_OFF");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_OFF_FIN, 0x0d, "STREAM_OFF_FIN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_OFF_LEN, 0x0e, "STREAM_OFF_LEN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_OFF_LEN_FIN, 0x0f, "STREAM_OFF_LEN_FIN");

        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::MAX_DATA, 0x10, "MAX_DATA");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::MAX_STREAM_DATA, 0x11, "MAX_STREAM_DATA");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::MAX_STREAMS_BIDI, 0x12, "MAX_STREAMS_BIDI");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::MAX_STREAMS_UNI, 0x13, "MAX_STREAMS_UNI");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::DATA_BLOCKED, 0x14, "DATA_BLOCKED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_DATA_BLOCKED, 0x15, "STREAM_DATA_BLOCKED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAMS_BLOCKED_BIDI,
                              0x16,
                              "STREAMS_BLOCKED_BIDI");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAMS_BLOCKED_UNI, 0x17, "STREAMS_BLOCKED_UNI");

        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::NEW_CONNECTION_ID, 0x18, "NEW_CONNECTION_ID");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::RETIRE_CONNECTION_ID,
                              0x19,
                              "RETIRE_CONNECTION_ID");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::PATH_CHALLENGE, 0x1a, "PATH_CHALLENGE");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::PATH_RESPONSE, 0x1b, "PATH_RESPONSE");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CONNECTION_CLOSE, 0x1c, "CONNECTION_CLOSE");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CONNECTION_CLOSE_APP,
                              0x1d,
                              "CONNECTION_CLOSE_APP");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::HANDSHAKE_DONE, 0x1e, "HANDSHAKE_DONE");
    }
};

// ---------------------------------------------------------------------------
// §2  RFC 9000 §19 — Backward-compatibility aliases (frame types)
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que os aliases de compatibilidade apontam para os novos valores RFC 9000.
 */
class QuicFrameTypeAliasesTestCase : public TestCase
{
  public:
    QuicFrameTypeAliasesTestCase()
        : TestCase("RFC 9000 §19 — backward-compat frame type aliases resolve to RFC values")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::RST_STREAM, 0x04, "RST_STREAM -> RESET_STREAM");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::APPLICATION_CLOSE,
                              0x1d,
                              "APPLICATION_CLOSE -> CONNECTION_CLOSE_APP");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::MAX_STREAM_ID,
                              0x12,
                              "MAX_STREAM_ID -> MAX_STREAMS_BIDI");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::BLOCKED, 0x14, "BLOCKED -> DATA_BLOCKED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_BLOCKED,
                              0x15,
                              "STREAM_BLOCKED -> STREAM_DATA_BLOCKED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_ID_BLOCKED,
                              0x16,
                              "STREAM_ID_BLOCKED -> STREAMS_BLOCKED_BIDI");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM000, 0x08, "STREAM000 -> STREAM");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM001, 0x09, "STREAM001 -> STREAM_FIN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM010, 0x0a, "STREAM010 -> STREAM_LEN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM011, 0x0b, "STREAM011 -> STREAM_LEN_FIN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM100, 0x0c, "STREAM100 -> STREAM_OFF");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM101, 0x0d, "STREAM101 -> STREAM_OFF_FIN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM110, 0x0e, "STREAM110 -> STREAM_OFF_LEN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM111,
                              0x0f,
                              "STREAM111 -> STREAM_OFF_LEN_FIN");
    }
};

// ---------------------------------------------------------------------------
// §3  RFC 9000 §20 — Transport error code wire values
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que todos os TransportErrorCodes_t têm os valores definidos pela RFC 9000 §20.
 */
class QuicTransportErrorCodeValuesTestCase : public TestCase
{
  public:
    QuicTransportErrorCodeValuesTestCase()
        : TestCase("RFC 9000 §20 — transport error code wire values match spec")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::NO_ERROR, 0x00, "NO_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::INTERNAL_ERROR, 0x01, "INTERNAL_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CONNECTION_REFUSED, 0x02, "CONNECTION_REFUSED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::FLOW_CONTROL_ERROR, 0x03, "FLOW_CONTROL_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_LIMIT_ERROR, 0x04, "STREAM_LIMIT_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_STATE_ERROR, 0x05, "STREAM_STATE_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::FINAL_SIZE_ERROR, 0x06, "FINAL_SIZE_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::FRAME_ENCODING_ERROR,
                              0x07,
                              "FRAME_ENCODING_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::TRANSPORT_PARAMETER_ERROR,
                              0x08,
                              "TRANSPORT_PARAMETER_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CONNECTION_ID_LIMIT_ERROR,
                              0x09,
                              "CONNECTION_ID_LIMIT_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::PROTOCOL_VIOLATION, 0x0a, "PROTOCOL_VIOLATION");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::INVALID_TOKEN, 0x0b, "INVALID_TOKEN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::APPLICATION_ERROR, 0x0c, "APPLICATION_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CRYPTO_BUFFER_EXCEEDED,
                              0x0d,
                              "CRYPTO_BUFFER_EXCEEDED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::KEY_UPDATE_ERROR, 0x0e, "KEY_UPDATE_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::AEAD_LIMIT_REACHED, 0x0f, "AEAD_LIMIT_REACHED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::NO_VIABLE_PATH, 0x10, "NO_VIABLE_PATH");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::CRYPTO_ERROR, 0x100, "CRYPTO_ERROR");
    }
};

// ---------------------------------------------------------------------------
// §4  RFC 9000 §20 — Backward-compatibility aliases (error codes)
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que os aliases de error codes apontam para os novos nomes RFC 9000.
 */
class QuicErrorCodeAliasesTestCase : public TestCase
{
  public:
    QuicErrorCodeAliasesTestCase()
        : TestCase("RFC 9000 §20 — backward-compat error code aliases resolve to RFC values")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::SERVER_BUSY,
                              0x02,
                              "SERVER_BUSY -> CONNECTION_REFUSED");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::STREAM_ID_ERROR,
                              0x04,
                              "STREAM_ID_ERROR -> STREAM_LIMIT_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::FINAL_OFFSET_ERROR,
                              0x06,
                              "FINAL_OFFSET_ERROR -> FINAL_SIZE_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::FRAME_FORMAT_ERROR,
                              0x07,
                              "FRAME_FORMAT_ERROR -> FRAME_ENCODING_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::VERSION_NEGOTIATION_ERROR,
                              0x09,
                              "VERSION_NEGOTIATION_ERROR -> CONNECTION_ID_LIMIT_ERROR");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::UNSOLICITED_PATH_ERROR,
                              0x0b,
                              "UNSOLICITED_PATH_ERROR -> INVALID_TOKEN");
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::FRAME_ERROR,
                              0x100,
                              "FRAME_ERROR -> CRYPTO_ERROR");
    }
};

// ---------------------------------------------------------------------------
// §5  RFC 9000 §19 — STREAM frame bit encoding (base 0x08)
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que CreateStreamSubHeader produz o byte de tipo correto segundo a
 * RFC 9000 §19.8: base=0x08, OFF=0x04, LEN=0x02, FIN=0x01.
 */
class QuicStreamFrameEncodingTestCase : public TestCase
{
  public:
    QuicStreamFrameEncodingTestCase()
        : TestCase("RFC 9000 §19.8 — STREAM frame type byte encoding (base=0x08)")
    {
    }

  private:
    void DoRun() override
    {
        // Sem flags: tipo deve ser 0x08
        QuicSubheader s000 = QuicSubheader::CreateStreamSubHeader(1, 0, 100, false, false, false);
        NS_TEST_ASSERT_MSG_EQ((int)s000.GetFrameType(), 0x08, "STREAM no flags");

        // FIN apenas: 0x08 | 0x01 = 0x09
        QuicSubheader s001 = QuicSubheader::CreateStreamSubHeader(1, 0, 100, false, false, true);
        NS_TEST_ASSERT_MSG_EQ((int)s001.GetFrameType(), 0x09, "STREAM FIN");

        // LEN apenas: 0x08 | 0x02 = 0x0a
        QuicSubheader s010 = QuicSubheader::CreateStreamSubHeader(1, 0, 100, false, true, false);
        NS_TEST_ASSERT_MSG_EQ((int)s010.GetFrameType(), 0x0a, "STREAM LEN");

        // LEN+FIN: 0x08 | 0x02 | 0x01 = 0x0b
        QuicSubheader s011 = QuicSubheader::CreateStreamSubHeader(1, 0, 100, false, true, true);
        NS_TEST_ASSERT_MSG_EQ((int)s011.GetFrameType(), 0x0b, "STREAM LEN+FIN");

        // OFF apenas: 0x08 | 0x04 = 0x0c
        QuicSubheader s100 = QuicSubheader::CreateStreamSubHeader(1, 10, 100, true, false, false);
        NS_TEST_ASSERT_MSG_EQ((int)s100.GetFrameType(), 0x0c, "STREAM OFF");

        // OFF+FIN: 0x08 | 0x04 | 0x01 = 0x0d
        QuicSubheader s101 = QuicSubheader::CreateStreamSubHeader(1, 10, 100, true, false, true);
        NS_TEST_ASSERT_MSG_EQ((int)s101.GetFrameType(), 0x0d, "STREAM OFF+FIN");

        // OFF+LEN: 0x08 | 0x04 | 0x02 = 0x0e
        QuicSubheader s110 = QuicSubheader::CreateStreamSubHeader(1, 10, 100, true, true, false);
        NS_TEST_ASSERT_MSG_EQ((int)s110.GetFrameType(), 0x0e, "STREAM OFF+LEN");

        // OFF+LEN+FIN: 0x08 | 0x04 | 0x02 | 0x01 = 0x0f
        QuicSubheader s111 = QuicSubheader::CreateStreamSubHeader(1, 10, 100, true, true, true);
        NS_TEST_ASSERT_MSG_EQ((int)s111.GetFrameType(), 0x0f, "STREAM OFF+LEN+FIN");
    }
};

// ---------------------------------------------------------------------------
// §6  RFC 9000 §19 — IsStream() identifica corretamente o range 0x08–0x0f
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que IsStream() retorna true para 0x08–0x0f e false fora do range.
 */
class QuicIsStreamTestCase : public TestCase
{
  public:
    QuicIsStreamTestCase()
        : TestCase("RFC 9000 §19.8 — IsStream() range [0x08, 0x0f]")
    {
    }

  private:
    void DoRun() override
    {
        // Todos os 8 tipos STREAM devem retornar IsStream() == true
        QuicSubheader::TypeFrame_t streamTypes[] = {QuicSubheader::STREAM,
                                                    QuicSubheader::STREAM_FIN,
                                                    QuicSubheader::STREAM_LEN,
                                                    QuicSubheader::STREAM_LEN_FIN,
                                                    QuicSubheader::STREAM_OFF,
                                                    QuicSubheader::STREAM_OFF_FIN,
                                                    QuicSubheader::STREAM_OFF_LEN,
                                                    QuicSubheader::STREAM_OFF_LEN_FIN};
        for (auto ft : streamTypes)
        {
            QuicSubheader sh = QuicSubheader::CreateStreamSubHeader(1, 0, 10);
            sh.SetFrameType(ft);
            NS_TEST_ASSERT_MSG_EQ(sh.IsStream(),
                                  true,
                                  "IsStream() deve ser true para 0x" << std::hex << (int)ft);
        }

        // Tipos não-STREAM devem retornar false
        QuicSubheader::TypeFrame_t nonStreamTypes[] = {QuicSubheader::PADDING,
                                                       QuicSubheader::PING,
                                                       QuicSubheader::ACK,
                                                       QuicSubheader::RESET_STREAM,
                                                       QuicSubheader::MAX_DATA,
                                                       QuicSubheader::CONNECTION_CLOSE,
                                                       QuicSubheader::HANDSHAKE_DONE};
        for (auto ft : nonStreamTypes)
        {
            QuicSubheader sh;
            sh.SetFrameType(ft);
            NS_TEST_ASSERT_MSG_EQ(sh.IsStream(),
                                  false,
                                  "IsStream() deve ser false para 0x" << std::hex << (int)ft);
        }
    }
};

// ---------------------------------------------------------------------------
// §7  RFC 9002 §5.3 — kInitialRtt = 333 ms
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que QuicSocketState inicializa kDefaultInitialRtt com 333 ms
 * conforme RFC 9002 §5.3 (era 100 ms no draft antigo).
 */
class QuicInitialRttTestCase : public TestCase
{
  public:
    QuicInitialRttTestCase()
        : TestCase("RFC 9002 §5.3 — kDefaultInitialRtt == 333 ms")
    {
    }

  private:
    void DoRun() override
    {
        QuicSocketState tcb;
        NS_TEST_ASSERT_MSG_EQ(tcb.m_kDefaultInitialRtt,
                              MilliSeconds(333),
                              "kDefaultInitialRtt deve ser 333 ms (RFC 9002 §5.3)");
    }
};

// ---------------------------------------------------------------------------
// §8  RFC 9002 §7.6.3 — kPersistentCongestionThreshold = 3
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que QuicSocketState inicializa kPersistentCongestionThreshold com 3
 * conforme recomendação da RFC 9002 §7.6.3.
 */
class QuicPersistentCongestionThresholdTestCase : public TestCase
{
  public:
    QuicPersistentCongestionThresholdTestCase()
        : TestCase("RFC 9002 §7.6.3 — kPersistentCongestionThreshold == 3")
    {
    }

  private:
    void DoRun() override
    {
        QuicSocketState tcb;
        NS_TEST_ASSERT_MSG_EQ(tcb.m_kPersistentCongestionThreshold,
                              (uint32_t)3,
                              "kPersistentCongestionThreshold deve ser 3 (RFC 9002 §7.6.3)");
    }
};

// ---------------------------------------------------------------------------
// §9  RFC 9002 §7.6.3 — Persistent congestion detection
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que OnPacketsLost() detecta persistent congestion e colapsa cwnd
 * para kMinimumWindow quando o span de envio dos pacotes perdidos excede a
 * duração de persistent congestion (RFC 9002 §7.6.3).
 */
class QuicPersistentCongestionDetectionTestCase : public TestCase
{
  public:
    QuicPersistentCongestionDetectionTestCase()
        : TestCase("RFC 9002 §7.6.3 — persistent congestion collapses cwnd to minimum")
    {
    }

  private:
    void DoRun() override
    {
        Simulator::Run();

        Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState>();
        tcb->m_kPersistentCongestionByPto =
            false; // these tests exercise the RFC 9002 duration rule

        // Configura RTT estimado: srtt=50ms, rttvar=10ms, maxAckDelay=0
        tcb->m_smoothedRtt = MilliSeconds(50);
        tcb->m_rttVar = MilliSeconds(10);
        tcb->m_latestRtt = MilliSeconds(50);
        tcb->m_maxAckDelay = Seconds(0);

        // persistent congestion duration = (50 + max(4*10, 1) + 0) * 3
        //                                = (50 + 40) * 3 = 270 ms
        Time persistentDuration = MilliSeconds(270);

        // Cwnd inicial grande para confirmar que foi colapsado
        tcb->m_cWnd = 100000;
        tcb->m_ssThresh = 100000;
        uint32_t minWin = tcb->m_kMinimumWindow;

        // Cria 2 pacotes perdidos cujo span (300 ms) > persistentDuration (270 ms)
        Ptr<Packet> pkt = Create<Packet>(500);

        Ptr<QuicSocketTxItem> p1 = CreateObject<QuicSocketTxItem>();
        p1->m_packet = pkt;
        p1->m_packetNumber = SequenceNumber32(1);
        p1->m_lastSent = MilliSeconds(0);
        p1->m_lost = true;

        Ptr<QuicSocketTxItem> p2 = CreateObject<QuicSocketTxItem>();
        p2->m_packet = pkt;
        p2->m_packetNumber = SequenceNumber32(2);
        p2->m_lastSent = MilliSeconds(300); // span = 300 ms > 270 ms
        p2->m_lost = true;

        std::vector<Ptr<QuicSocketTxItem>> lostPackets = {p1, p2};

        // Chama OnPacketsLost
        QuicCongestionOps cc;
        cc.OnPacketsLost(tcb, lostPackets);

        // Persistent congestion deve ter colapsado cwnd para kMinimumWindow
        NS_TEST_ASSERT_MSG_EQ(
            tcb->m_cWnd,
            minWin,
            "cwnd deve colapsar para kMinimumWindow ao detectar persistent congestion");
        // RFC 9002 s7.6.2: only cwnd collapses; ssthresh keeps what the congestion event set (half
        // of 100000), so slow start resumes from the minimum window
        NS_TEST_ASSERT_MSG_EQ(
            tcb->m_ssThresh,
            50000u,
            "ssThresh mantem o valor do evento de congestionamento (RFC 9002 s7.6.2)");
        NS_TEST_ASSERT_MSG_LT(tcb->m_cWnd,
                              tcb->m_ssThresh,
                              "depois do persistent congestion o sender volta ao slow start");
        // min_rtt deve ser resetado para latest_rtt
        NS_TEST_ASSERT_MSG_EQ(tcb->m_minRtt,
                              tcb->m_latestRtt,
                              "minRtt deve ser resetado para latestRtt apos persistent congestion");

        Simulator::Destroy();
    }
};

// ---------------------------------------------------------------------------
// §10  RFC 9002 §7.6.3 — Persistent congestion NÃO dispara com span pequeno
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que OnPacketsLost() NÃO declara persistent congestion quando o span
 * de envio dos pacotes perdidos é menor que a duração de persistent congestion.
 */
class QuicNoPersistentCongestionTestCase : public TestCase
{
  public:
    QuicNoPersistentCongestionTestCase()
        : TestCase("RFC 9002 §7.6.3 — no persistent congestion when span < duration")
    {
    }

  private:
    void DoRun() override
    {
        Simulator::Run();

        Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState>();
        tcb->m_kPersistentCongestionByPto =
            false; // these tests exercise the RFC 9002 duration rule

        tcb->m_smoothedRtt = MilliSeconds(50);
        tcb->m_rttVar = MilliSeconds(10);
        tcb->m_latestRtt = MilliSeconds(50);
        tcb->m_maxAckDelay = Seconds(0);

        // persistent congestion duration = 270 ms (ver §9 acima)
        uint32_t bigCwnd = 100000;
        tcb->m_cWnd = bigCwnd;
        tcb->m_ssThresh = bigCwnd;

        Ptr<Packet> pkt = Create<Packet>(500);

        Ptr<QuicSocketTxItem> p1 = CreateObject<QuicSocketTxItem>();
        p1->m_packet = pkt;
        p1->m_packetNumber = SequenceNumber32(1);
        p1->m_lastSent = MilliSeconds(0);
        p1->m_lost = true;

        Ptr<QuicSocketTxItem> p2 = CreateObject<QuicSocketTxItem>();
        p2->m_packet = pkt;
        p2->m_packetNumber = SequenceNumber32(2);
        p2->m_lastSent = MilliSeconds(100); // span = 100 ms < 270 ms
        p2->m_lost = true;

        std::vector<Ptr<QuicSocketTxItem>> lostPackets = {p1, p2};

        QuicCongestionOps cc;
        cc.OnPacketsLost(tcb, lostPackets);

        // cwnd foi reduzido pelo recovery normal (×0.5), mas NÃO colapsado ao mínimo
        uint32_t minWin = tcb->m_kMinimumWindow;
        NS_TEST_ASSERT_MSG_GT(
            tcb->m_cWnd,
            minWin,
            "cwnd nao deve colapsar para minimo quando span < persistent congestion duration");

        Simulator::Destroy();
    }
};

// ---------------------------------------------------------------------------
// §11  RFC 9002 §7.6.3 — Persistent congestion requer amostra de RTT prévia
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que OnPacketsLost() NÃO detecta persistent congestion quando
 * smoothedRtt == 0 (sem amostra de RTT real ainda).
 */
class QuicPersistentCongestionNoRttTestCase : public TestCase
{
  public:
    QuicPersistentCongestionNoRttTestCase()
        : TestCase("RFC 9002 §7.6.3 — persistent congestion requires prior RTT sample")
    {
    }

  private:
    void DoRun() override
    {
        Simulator::Run();

        Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState>();
        tcb->m_kPersistentCongestionByPto =
            false; // these tests exercise the RFC 9002 duration rule

        // Sem amostra de RTT (smoothedRtt = 0)
        tcb->m_smoothedRtt = Seconds(0);
        tcb->m_rttVar = Seconds(0);
        tcb->m_latestRtt = Seconds(0);
        tcb->m_maxAckDelay = Seconds(0);

        uint32_t bigCwnd = 100000;
        tcb->m_cWnd = bigCwnd;
        tcb->m_ssThresh = bigCwnd;

        Ptr<Packet> pkt = Create<Packet>(500);

        Ptr<QuicSocketTxItem> p1 = CreateObject<QuicSocketTxItem>();
        p1->m_packet = pkt;
        p1->m_packetNumber = SequenceNumber32(1);
        p1->m_lastSent = MilliSeconds(0);
        p1->m_lost = true;

        Ptr<QuicSocketTxItem> p2 = CreateObject<QuicSocketTxItem>();
        p2->m_packet = pkt;
        p2->m_packetNumber = SequenceNumber32(2);
        p2->m_lastSent = Seconds(10); // span enorme, mas sem RTT sample
        p2->m_lost = true;

        std::vector<Ptr<QuicSocketTxItem>> lostPackets = {p1, p2};

        QuicCongestionOps cc;
        cc.OnPacketsLost(tcb, lostPackets);

        uint32_t minWin = tcb->m_kMinimumWindow;
        NS_TEST_ASSERT_MSG_GT(tcb->m_cWnd,
                              minWin,
                              "persistent congestion nao deve disparar sem amostra previa de RTT");

        Simulator::Destroy();
    }
};

// ---------------------------------------------------------------------------
// §12  RFC 9000 §17.3.1 — Spin Bit in short header
// ---------------------------------------------------------------------------

#include "../model/quic-header.h"

/**
 * @ingroup quic-tests
 * Verifica que o Spin Bit é serializado e desserializado corretamente.
 */
class QuicSpinBitTestCase : public TestCase
{
  public:
    QuicSpinBitTestCase()
        : TestCase("RFC 9000 s17.3.1 spin bit serialize and deserialize")
    {
    }

  private:
    void DoRun() override
    {
        // Create short header with spin bit = 0
        QuicHeader h0 = QuicHeader::CreateShort(0xDEADBEEF,
                                                SequenceNumber32(42),
                                                true,
                                                QuicHeader::PHASE_ZERO,
                                                false);
        NS_TEST_ASSERT_MSG_EQ(h0.GetSpinBit(), false, "spin bit 0 set");

        // Create short header with spin bit = 1
        QuicHeader h1 = QuicHeader::CreateShort(0xDEADBEEF,
                                                SequenceNumber32(43),
                                                true,
                                                QuicHeader::PHASE_ZERO,
                                                true);
        NS_TEST_ASSERT_MSG_EQ(h1.GetSpinBit(), true, "spin bit 1 set");

        // Serialize h1 and deserialize — spin bit must round-trip
        uint32_t sz = h1.GetSerializedSize();
        Buffer buf;
        buf.AddAtEnd(sz);
        Buffer::Iterator wit = buf.Begin();
        h1.Serialize(wit);

        QuicHeader h2;
        Buffer::Iterator rit = buf.Begin();
        h2.Deserialize(rit);

        NS_TEST_ASSERT_MSG_EQ(h2.GetSpinBit(), true, "spin bit round-trip");
        NS_TEST_ASSERT_MSG_EQ(h2.GetKeyPhaseBit(), false, "key phase round-trip after spin bit");
    }
};

// ---------------------------------------------------------------------------
// §13  RFC 9000 §18.2 — Transport params: active_connection_id_limit ≥ 2
// ---------------------------------------------------------------------------

#include "../model/quic-transport-parameters.h"

/**
 * @ingroup quic-tests
 * Verifica que active_connection_id_limit padrão é ≥2 (RFC 9000 §18.2).
 */
class QuicActiveConnIdLimitTestCase : public TestCase
{
  public:
    QuicActiveConnIdLimitTestCase()
        : TestCase("RFC 9000 s18.2 active_connection_id_limit >= 2")
    {
    }

  private:
    void DoRun() override
    {
        QuicTransportParameters tp;
        NS_TEST_ASSERT_MSG_EQ(tp.GetActiveConnectionIdLimit() >= 2,
                              true,
                              "active_connection_id_limit must be >= 2");
    }
};

/**
 * @ingroup quic-tests
 * Verifica que stateless_reset_token é serializado/desserializado corretamente.
 */
class QuicStatelessResetTokenTestCase : public TestCase
{
  public:
    QuicStatelessResetTokenTestCase()
        : TestCase("RFC 9000 s18.2 stateless reset token round-trip")
    {
    }

  private:
    void DoRun() override
    {
        QuicTransportParameters tp;
        tp.SetStatelessResetToken(0xDEADBEEFCAFEBABEULL, 0xFEEDFACECAFED00DULL);

        uint32_t sz = tp.GetSerializedSize();
        Buffer buf;
        buf.AddAtEnd(sz);
        Buffer::Iterator wit = buf.Begin();
        tp.Serialize(wit);

        QuicTransportParameters tp2;
        Buffer::Iterator rit = buf.Begin();
        tp2.Deserialize(rit);

        NS_TEST_ASSERT_MSG_EQ(tp2.GetStatelessResetTokenHi(), 0xDEADBEEFCAFEBABEULL, "token hi");
        NS_TEST_ASSERT_MSG_EQ(tp2.GetStatelessResetTokenLo(), 0xFEEDFACECAFED00DULL, "token lo");
    }
};

// ---------------------------------------------------------------------------
// §14  RFC 9000 §20 — FRAME_ENCODING_ERROR code present
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que FRAME_ENCODING_ERROR está definido com valor correto (RFC 9000 §20).
 */
class QuicFrameEncodingErrorTestCase : public TestCase
{
  public:
    QuicFrameEncodingErrorTestCase()
        : TestCase("RFC 9000 s20 FRAME_ENCODING_ERROR wire value")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ((int)QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
                              0x07,
                              "FRAME_ENCODING_ERROR must be 0x07 per RFC 9000 §20");
    }
};

// ---------------------------------------------------------------------------
// TestSuite
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * TestSuite para o módulo QUIC — RFC 9000 e RFC 9002
 */
// ---------------------------------------------------------------------------
// End-to-end: ordered, complete delivery on several streams, with loss and with
// small flow-control windows (msquic-like behaviour)
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Server sends a patterned byte sequence on three streams over a lossy bottleneck;
 * the client checks that every stream arrives complete and in order.
 */
class QuicEndToEndTestCase : public TestCase
{
  public:
    QuicEndToEndTestCase(std::string name,
                         double loss,
                         uint32_t maxStreamData,
                         uint32_t maxData,
                         uint32_t stopStream = 0)
        : TestCase(name),
          m_loss(loss),
          m_maxStreamData(maxStreamData),
          m_maxData(maxData),
          m_stopStream(stopStream)
    {
    }

  private:
    static constexpr uint32_t kBytesPerStream = 300000;

    void DoRun() override
    {
        if (const char* only = std::getenv("QUIC_E2E_ONLY"))
        {
            if (GetName() != only)
            {
                return;
            }
        }
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(8));
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdUni", UintegerValue(8));
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamData", UintegerValue(m_maxStreamData));
        Config::SetDefault("ns3::QuicSocketBase::MaxData", UintegerValue(m_maxData));
        RngSeedManager::SetSeed(1);
        RngSeedManager::SetRun(3);

        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("20ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        if (m_loss > 0)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetAttribute("ErrorRate", DoubleValue(m_loss));
            em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
            dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        }
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.1.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicEndToEndTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicEndToEndTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(120));
        Simulator::Run();
        Simulator::Destroy();

        for (uint32_t sid = 1; sid <= 3; ++sid)
        {
            if (sid == m_stopStream)
            {
                NS_TEST_ASSERT_MSG_LT(m_rx[sid],
                                      kBytesPerStream,
                                      "stream " << sid << " should have been cut short");
                NS_TEST_ASSERT_MSG_EQ(m_resetSeenByServer,
                                      true,
                                      "server did not reset stream " << sid);
                NS_TEST_ASSERT_MSG_EQ(m_resetSeenByClient,
                                      true,
                                      "client did not see the reset of stream " << sid);
                continue;
            }
            NS_TEST_ASSERT_MSG_EQ(m_rx[sid], kBytesPerStream, "stream " << sid << " incomplete");
        }
        NS_TEST_ASSERT_MSG_EQ(m_corrupt, false, "out-of-order or corrupted bytes");
    }

    void ResetTrace(bool byPeer, uint64_t id, uint16_t err, bool peer)
    {
        if (id == ServerStreamId(m_stopStream) && err == 7)
        {
            (byPeer ? m_resetSeenByClient : m_resetSeenByServer) = true;
        }
        (void)peer;
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        for (uint32_t sid = 1; sid <= 3; ++sid)
        {
            for (uint32_t off = 0; off < kBytesPerStream; off += 1000)
            {
                std::vector<uint8_t> buf(1000);
                for (uint32_t i = 0; i < 1000; ++i)
                {
                    buf[i] = (uint8_t)((off + i) & 0xff);
                }
                s->Send(Create<Packet>(buf.data(), buf.size()), ServerStreamId(sid));
            }
        }
        if (m_stopStream != 0)
        {
            m_server = s;
            // Hook every stream's reset trace on the server side once they exist
            Simulator::Schedule(Seconds(0.0001), [this]() { PollServerTraces(); });
        }
        // Close right after writing: buffered data must still be flushed (FlushOnClose)
        s->Close();
    }

    // The server streams exist only once the handshake ended: poll until the traced stream is there
    void PollServerTraces()
    {
        Ptr<QuicSocketBase> qs = DynamicCast<QuicSocketBase>(m_server);
        if (qs->GetQuicL5()->SearchStream(ServerStreamId(m_stopStream)) == nullptr)
        {
            Simulator::Schedule(MilliSeconds(1), [this]() { PollServerTraces(); });
            return;
        }
        ConnectTraces(true);
    }

    void ConnectTraces(bool server)
    {
        Ptr<QuicSocketBase> qs = DynamicCast<QuicSocketBase>(server ? m_server : m_client);
        for (uint32_t sid = 1; sid <= 3; ++sid)
        {
            Ptr<QuicStreamBase> st = qs->GetQuicL5()->SearchStream(ServerStreamId(sid));
            if (st && sid == m_stopStream)
            {
                st->TraceConnectWithoutContext(
                    "StreamReset",
                    MakeBoundCallback(&QuicEndToEndTestCase::TraceThunk, this, !server));
            }
        }
    }

    static void TraceThunk(QuicEndToEndTestCase* t,
                           bool byPeer,
                           uint64_t id,
                           uint16_t err,
                           bool peer)
    {
        t->ResetTrace(byPeer, id, err, peer);
    }

    void Read(Ptr<Socket> s)
    {
        if (m_stopStream != 0 && !m_stopIssued)
        {
            Ptr<QuicSocketBase> qs = DynamicCast<QuicSocketBase>(s);
            if (qs->GetQuicL5()->SearchStream(ServerStreamId(m_stopStream)) != nullptr)
            {
                m_stopIssued = true;
                ConnectTraces(false);
                qs->StopSending(ServerStreamId(m_stopStream), 7);
            }
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
                uint32_t sid = LogicalStream(tag.GetStreamId());
                for (uint32_t i = item.GetStart(); i < item.GetEnd(); ++i)
                {
                    if (raw[i] != (uint8_t)(m_rx[sid] & 0xff))
                    {
                        m_corrupt = true;
                    }
                    m_rx[sid]++;
                }
            }
        }
    }

    double m_loss;
    uint32_t m_maxStreamData;
    uint32_t m_maxData;
    std::map<uint32_t, uint32_t> m_rx;
    bool m_corrupt{false};
    uint32_t m_stopStream;
    bool m_stopIssued{false};
    bool m_resetSeenByServer{false};
    bool m_resetSeenByClient{false};
    Ptr<Socket> m_server;
    Ptr<Socket> m_listen;
    Ptr<Socket> m_client;
};

/**
 * Link blackout: a short outage must be survived (all data delivered), a permanent one must
 * make the sender give up after DisconnectTimeout (msquic: 16 s without progress).
 */
class QuicBlackoutTestCase : public TestCase
{
  public:
    QuicBlackoutTestCase(std::string name, Time outage, Time start = Seconds(1.5))
        : TestCase(name),
          m_outage(outage),
          m_start(start)
    {
    }

  private:
    static constexpr uint32_t kTotal = 600000;

    void DoRun() override
    {
        if (const char* only = std::getenv("QUIC_E2E_ONLY"))
        {
            if (GetName() != only)
            {
                return;
            }
        }
        RngSeedManager::SetSeed(1);
        RngSeedManager::SetRun(5);
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("2Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("20ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        for (uint32_t i = 0; i < 2; ++i)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetAttribute("ErrorRate", DoubleValue(1.0));
            em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
            em->Disable();
            dev.Get(i)->SetAttribute("ReceiveErrorModel", PointerValue(em));
            m_em[i] = em;
        }
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.2.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicBlackoutTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicBlackoutTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        // The outage starts while data is in flight
        Simulator::Schedule(m_start, [this]() { SetOutage(true); });
        if (m_outage.IsStrictlyPositive())
        {
            Simulator::Schedule(m_start + m_outage, [this]() { SetOutage(false); });
        }
        Simulator::Stop(Seconds(200));
        Simulator::Run();
        Simulator::Destroy();

        if (m_outage.IsStrictlyPositive())
        {
            NS_TEST_ASSERT_MSG_EQ(m_errorClosedAt.IsZero(),
                                  true,
                                  "connection died during a short outage");
            NS_TEST_ASSERT_MSG_EQ(m_rx, kTotal, "data lost across the outage");
        }
        else
        {
            NS_TEST_ASSERT_MSG_EQ(m_errorClosedAt.IsStrictlyPositive(),
                                  true,
                                  "connection never gave up");
            Time elapsed = m_errorClosedAt - m_start;
            NS_TEST_ASSERT_MSG_GT(elapsed, Seconds(15), "gave up before DisconnectTimeout (16 s)");
            NS_TEST_ASSERT_MSG_LT(elapsed, Seconds(60), "gave up far later than DisconnectTimeout");
        }
    }

    void SetOutage(bool on)
    {
        for (auto& em : m_em)
        {
            if (on)
            {
                em->Enable();
            }
            else
            {
                em->Disable();
            }
        }
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        s->SetCloseCallbacks(MakeNullCallback<void, Ptr<Socket>>(),
                             MakeCallback(&QuicBlackoutTestCase::ErrorClose, this));
        for (uint32_t off = 0; off < kTotal; off += 1000)
        {
            s->Send(Create<Packet>(1000), 1);
        }
        s->Close();
    }

    void ErrorClose(Ptr<Socket>)
    {
        m_errorClosedAt = Simulator::Now();
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            m_rx += p->GetSize();
        }
    }

    Time m_outage;
    Time m_start;
    Ptr<RateErrorModel> m_em[2];
    uint32_t m_rx{0};
    Time m_errorClosedAt{Seconds(0)};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_client;
};

/**
 * Error model that never drops: it holds back a random fraction of the packets and re-injects
 * them later, reordering the stream without any real loss.
 */
class ReorderingModel : public ErrorModel
{
  public:
    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::QuicTestReorderingModel")
                                .SetParent<ErrorModel>()
                                .AddConstructor<ReorderingModel>();
        return tid;
    }

    void Setup(Ptr<PointToPointNetDevice> dev, double fraction, Time extra)
    {
        m_dev = dev;
        m_fraction = fraction;
        m_extra = extra;
        m_rng = CreateObject<UniformRandomVariable>();
    }

    uint32_t Held(void) const
    {
        return m_held;
    }

  private:
    bool DoCorrupt(Ptr<Packet> p) override
    {
        if (m_reinjecting || m_rng->GetValue() >= m_fraction)
        {
            return false;
        }
        m_held++;
        Simulator::Schedule(m_extra, &ReorderingModel::Reinject, this, p->Copy());
        return true;
    }

    void Reinject(Ptr<Packet> p)
    {
        m_reinjecting = true;
        m_dev->Receive(p);
        m_reinjecting = false;
    }

    void DoReset(void) override
    {
    }

    Ptr<PointToPointNetDevice> m_dev;
    Ptr<UniformRandomVariable> m_rng;
    double m_fraction{0};
    Time m_extra;
    bool m_reinjecting{false};
    uint32_t m_held{0};
};

/**
 * Pure reordering (no loss): everything must still be delivered, and packets wrongly declared
 * lost must be reported as spurious so that the congestion state is restored.
 */
class QuicReorderingTestCase : public TestCase
{
  public:
    QuicReorderingTestCase()
        : TestCase("reordering without loss triggers spurious-loss undo")
    {
    }

  private:
    static constexpr uint32_t kTotal = 1500000;

    void DoRun() override
    {
        RngSeedManager::SetSeed(1);
        RngSeedManager::SetRun(7);
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("20ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        m_model = CreateObject<ReorderingModel>();
        m_model->Setup(DynamicCast<PointToPointNetDevice>(dev.Get(1)), 0.03, MilliSeconds(12));
        dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(m_model));
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.3.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicReorderingTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicReorderingTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(60));
        Simulator::Run();
        uint32_t held = m_model->Held();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_GT(held, 10u, "the model did not reorder anything");
        NS_TEST_ASSERT_MSG_EQ(m_rx, kTotal, "data lost on a loss-free reordering link");
        NS_TEST_ASSERT_MSG_GT(m_spurious, 0u, "reordering was never detected as spurious loss");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        DynamicCast<QuicSocketBase>(s)->TraceConnectWithoutContext(
            "SpuriousLoss",
            MakeCallback(&QuicReorderingTestCase::OnSpurious, this));
        for (uint32_t off = 0; off < kTotal; off += 1000)
        {
            s->Send(Create<Packet>(1000), 1);
        }
        s->Close();
    }

    void OnSpurious(uint32_t)
    {
        m_spurious++;
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            m_rx += p->GetSize();
        }
    }

    Ptr<ReorderingModel> m_model;
    uint32_t m_rx{0};
    uint32_t m_spurious{0};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_client;
};

/**
 * Stream priority end to end: a small message on stream 2, written after a 400 KB backlog on
 * stream 1, must not wait for the backlog when stream 2 has a higher priority.
 */
/**
 * msquic default stream scheduling (QUIC_STREAM_SCHEDULING_SCHEME_FIFO): a stream keeps its place
 * while it has data queued, so data written later on an already queued stream is served before
 * a stream that became backlogged after it; priority overrides the order.
 */
class QuicStreamFifoSchedulerTestCase : public TestCase
{
  public:
    QuicStreamFifoSchedulerTestCase()
        : TestCase("stream FIFO scheduler keeps a backlogged stream at the front")
    {
    }

  private:
    static Ptr<QuicSocketTxItem> Item(uint64_t stream, uint64_t offset)
    {
        Ptr<QuicSocketTxItem> it = CreateObject<QuicSocketTxItem>();
        it->m_packet = Create<Packet>(100);
        it->m_packet->AddHeader(
            QuicSubheader::CreateStreamSubHeader(stream, offset, 100, offset != 0, true, false));
        it->m_isStream = true;
        return it;
    }

    std::vector<uint64_t> Drain(Ptr<QuicSocketTxScheduler> sched)
    {
        std::vector<uint64_t> order;
        Ptr<QuicSocketTxItem> out = sched->GetNewSegment(100000);
        Ptr<Packet> pkt = out->m_packet->Copy();
        while (pkt->GetSize() > 0)
        {
            QuicSubheader qsb;
            pkt->RemoveHeader(qsb);
            order.push_back(qsb.GetStreamId());
            pkt->RemoveAtStart(std::min<uint32_t>(qsb.GetLength(), pkt->GetSize()));
        }
        return order;
    }

    void DoRun() override
    {
        // stream 1 queued, then stream 2, then more data for stream 1
        Ptr<QuicSocketTxStreamFifoScheduler> fifo = CreateObject<QuicSocketTxStreamFifoScheduler>();
        fifo->Add(Item(1, 0), false);
        fifo->Add(Item(2, 0), false);
        fifo->Add(Item(1, 100), false);
        std::vector<uint64_t> order = Drain(fifo);
        NS_TEST_ASSERT_MSG_EQ(order.size() >= 2, true, "frames not drained");
        NS_TEST_ASSERT_MSG_EQ(order[0], 1u, "stream 1 must be served first");
        NS_TEST_ASSERT_MSG_EQ(order.back(),
                              2u,
                              "stream 2 must wait for stream 1's later data (FIFO per stream)");

        Ptr<QuicSocketTxStreamFifoScheduler> prio = CreateObject<QuicSocketTxStreamFifoScheduler>();
        prio->SetStreamPriority(2, 0xFFFF);
        prio->Add(Item(1, 0), false);
        prio->Add(Item(2, 0), false);
        order = Drain(prio);
        NS_TEST_ASSERT_MSG_EQ(order[0], 2u, "higher priority stream must go first");
    }
};

/**
 * msquic round-robin stream scheduling: streams take turns in batches of 8 packets, so a small
 * stream queued behind a large backlog is served after the current turn of the large stream, not
 * after all of it.
 */
class QuicRoundRobinSchedulerTestCase : public TestCase
{
  public:
    QuicRoundRobinSchedulerTestCase()
        : TestCase("round-robin scheduler serves a small stream after one turn of the backlog")
    {
    }

  private:
    static Ptr<QuicSocketTxItem> Item(uint64_t stream, uint64_t offset)
    {
        Ptr<QuicSocketTxItem> it = CreateObject<QuicSocketTxItem>();
        it->m_packet = Create<Packet>(100);
        it->m_packet->AddHeader(
            QuicSubheader::CreateStreamSubHeader(stream, offset, 100, offset != 0, true, false));
        it->m_isStream = true;
        return it;
    }

    size_t PositionOfSmallStream(Ptr<QuicSocketTxScheduler> sched)
    {
        for (uint32_t i = 0; i < 300; ++i)
        {
            sched->Add(Item(1, i * 100), false);
        }
        sched->Add(Item(2, 0), false);
        Ptr<QuicSocketTxItem> out = sched->GetNewSegment(100000);
        Ptr<Packet> pkt = out->m_packet->Copy();
        size_t position = 0;
        size_t n = 0;
        while (pkt->GetSize() > 0)
        {
            QuicSubheader qsb;
            pkt->RemoveHeader(qsb);
            if (qsb.GetStreamId() == 2)
            {
                position = n;
            }
            ++n;
            pkt->RemoveAtStart(std::min<uint32_t>(qsb.GetLength(), pkt->GetSize()));
        }
        return position;
    }

    void DoRun() override
    {
        size_t fifo = PositionOfSmallStream(CreateObject<QuicSocketTxStreamFifoScheduler>());
        size_t rr = PositionOfSmallStream(CreateObject<QuicSocketTxRoundRobinScheduler>());
        NS_TEST_ASSERT_MSG_GT(fifo,
                              250u,
                              "FIFO per stream serves the small stream after the whole backlog");
        NS_TEST_ASSERT_MSG_LT(rr,
                              130u,
                              "round-robin serves it after one turn (8 packets of 1460 bytes)");
    }
};

class QuicStreamPriorityTestCase : public TestCase
{
  public:
    QuicStreamPriorityTestCase(std::string name, bool prioritize)
        : TestCase(name),
          m_prioritize(prioritize)
    {
    }

  private:
    void DoRun() override
    {
        RngSeedManager::SetSeed(1);
        RngSeedManager::SetRun(9);
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("20ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.4.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicStreamPriorityTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicStreamPriorityTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(30));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_rx[1], 400000u, "stream 1 incomplete");
        NS_TEST_ASSERT_MSG_EQ(m_rx[2], 100u, "stream 2 incomplete");
        if (m_prioritize)
        {
            NS_TEST_ASSERT_MSG_LT(m_stream2At,
                                  m_stream1DoneAt,
                                  "prioritized stream waited for the backlog");
        }
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        if (m_prioritize)
        {
            DynamicCast<QuicSocketBase>(s)->SetStreamPriority(ServerStreamId(2), 0xFFFF);
        }
        for (uint32_t off = 0; off < 400000; off += 1000)
        {
            s->Send(Create<Packet>(1000), 1);
        }
        Simulator::Schedule(MilliSeconds(200),
                            [s]() { s->Send(Create<Packet>(100), ServerStreamId(2)); });
        Simulator::Schedule(MilliSeconds(300), [s]() { s->Close(); });
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            for (ByteTagIterator it = p->GetByteTagIterator(); it.HasNext();)
            {
                ByteTagIterator::Item item = it.Next();
                if (item.GetTypeId() != QuicStreamIdTag::GetTypeId())
                {
                    continue;
                }
                QuicStreamIdTag tag;
                item.GetTag(tag);
                uint32_t sid = LogicalStream(tag.GetStreamId());
                m_rx[sid] += item.GetEnd() - item.GetStart();
                if (sid == 2 && m_stream2At.IsZero())
                {
                    m_stream2At = Simulator::Now();
                }
                if (sid == 1 && m_rx[1] == 400000u)
                {
                    m_stream1DoneAt = Simulator::Now();
                }
            }
        }
    }

    bool m_prioritize;
    std::map<uint32_t, uint32_t> m_rx;
    Time m_stream2At{Seconds(0)};
    Time m_stream1DoneAt{Seconds(0)};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_client;
};

/**
 * CUBIC reactions that msquic defines: a loss reduces cwnd by BETA 0.7 and a spurious one is
 * undone; a loss after more than 2 consecutive PTOs is persistent congestion (cwnd = 2 packets,
 * ssthresh = 0.7 of the previous window).
 */
class QuicCubicEventsTestCase : public TestCase
{
  public:
    QuicCubicEventsTestCase()
        : TestCase("CUBIC: loss, spurious-loss undo and persistent congestion (msquic)")
    {
    }

  private:
    static std::vector<Ptr<QuicSocketTxItem>> LostPacket(uint32_t pn)
    {
        Ptr<QuicSocketTxItem> it = CreateObject<QuicSocketTxItem>();
        it->m_packet = Create<Packet>(500);
        it->m_packetNumber = SequenceNumber32(pn);
        it->m_lastSent = Seconds(0);
        it->m_lost = true;
        return {it};
    }

    Ptr<QuicSocketState> NewState()
    {
        Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState>();
        tcb->m_cWnd = 100000;
        tcb->m_ssThresh = 100000;
        tcb->m_highTxMark = SequenceNumber32(50);
        return tcb;
    }

    void DoRun() override
    {
        Simulator::Run();
        // loss, then undone because the packet was only reordered
        Ptr<QuicSocketState> tcb = NewState();
        Ptr<QuicCubic> cc = CreateObject<QuicCubic>();
        cc->OnPacketsLost(tcb, LostPacket(5));
        NS_TEST_ASSERT_MSG_EQ_TOL((double)tcb->m_cWnd.Get(), 70000.0, 100.0, "BETA 0.7 reduction");
        cc->OnSpuriousLoss(tcb, SequenceNumber32(5));
        NS_TEST_ASSERT_MSG_EQ(tcb->m_cWnd.Get() >= 100000u,
                              true,
                              "spurious loss must restore cwnd");

        // loss after 3 PTOs: persistent congestion
        tcb = NewState();
        tcb->m_ptoCountForLoss = 3;
        cc = CreateObject<QuicCubic>();
        cc->OnPacketsLost(tcb, LostPacket(5));
        NS_TEST_ASSERT_MSG_EQ(tcb->m_cWnd.Get(),
                              tcb->m_kMinimumWindow,
                              "persistent congestion: cwnd = 2 packets");
        NS_TEST_ASSERT_MSG_EQ_TOL((double)tcb->m_ssThresh.Get(),
                                  70000.0,
                                  100.0,
                                  "persistent congestion: ssthresh = 0.7 cwnd");

        // exactly 2 PTOs is not persistent congestion
        tcb = NewState();
        tcb->m_ptoCountForLoss = 2;
        cc = CreateObject<QuicCubic>();
        cc->OnPacketsLost(tcb, LostPacket(5));
        NS_TEST_ASSERT_MSG_EQ_TOL((double)tcb->m_cWnd.Get(),
                                  70000.0,
                                  100.0,
                                  "2 PTOs are an ordinary loss");
        Simulator::Destroy();
    }
};

/**
 * msquic idle timeout (30 s): a connection that exchanges nothing for that long is closed.
 */
class QuicIdleTimeoutTestCase : public TestCase
{
  public:
    QuicIdleTimeoutTestCase()
        : TestCase("idle connection closes after the 30 s idle timeout")
    {
    }

  private:
    void DoRun() override
    {
        if (const char* only = std::getenv("QUIC_E2E_ONLY"))
        {
            if (GetName() != only)
            {
                return;
            }
        }
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.5.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicIdleTimeoutTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetCloseCallbacks(MakeCallback(&QuicIdleTimeoutTestCase::Closed, this),
                                    MakeCallback(&QuicIdleTimeoutTestCase::Closed, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(120));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_closedAt.IsStrictlyPositive(),
                              true,
                              "idle connection never closed");
        NS_TEST_ASSERT_MSG_GT(m_closedAt, Seconds(29), "closed before the idle timeout");
        NS_TEST_ASSERT_MSG_LT(m_closedAt, Seconds(45), "closed long after the idle timeout");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        s->Send(Create<Packet>(500), 1);
    }

    void Closed(Ptr<Socket>)
    {
        if (m_closedAt.IsZero())
        {
            m_closedAt = Simulator::Now();
        }
    }

    Time m_closedAt{Seconds(0)};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_client;
};

/** Drops every packet larger than a limit: a path whose MTU is smaller than the probes. */
class SizeLimitModel : public ErrorModel
{
  public:
    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::QuicTestSizeLimitModel")
                                .SetParent<ErrorModel>()
                                .AddConstructor<SizeLimitModel>();
        return tid;
    }

    void SetLimit(uint32_t limit)
    {
        m_limit = limit;
    }

  private:
    bool DoCorrupt(Ptr<Packet> p) override
    {
        return p->GetSize() > m_limit;
    }

    void DoReset(void) override
    {
    }

    uint32_t m_limit{UINT32_MAX};
};

/**
 * DPLPMTUD (msquic): the connection starts at a 1288 byte MTU and grows in 80 byte steps, with 1500
 * always tried; probes larger than the path allows are retried three times and then the search
 * ends.
 */
class QuicMtuDiscoveryTestCase : public TestCase
{
  public:
    QuicMtuDiscoveryTestCase(std::string name, uint32_t pathMtu, uint32_t expectedMtu)
        : TestCase(name),
          m_pathMtu(pathMtu),
          m_expectedMtu(expectedMtu)
    {
    }

  private:
    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        for (uint32_t i = 0; i < 2; ++i)
        {
            Ptr<SizeLimitModel> em = CreateObject<SizeLimitModel>();
            // device frames carry 2 bytes of PPP header on top of the IP packet
            em->SetLimit(m_pathMtu + 2);
            dev.Get(i)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        }
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.6.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicMtuDiscoveryTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(15));
        Simulator::Run();
        uint32_t clientMtu = DynamicCast<QuicSocketBase>(m_client)->GetSegSize() + 41;
        uint32_t serverMtu = DynamicCast<QuicSocketBase>(m_server)->GetSegSize() + 41;
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(clientMtu, m_expectedMtu, "client path MTU");
        NS_TEST_ASSERT_MSG_EQ(serverMtu, m_expectedMtu, "server path MTU");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
        for (uint32_t off = 0; off < 200000; off += 1000)
        {
            s->Send(Create<Packet>(1000), 1);
        }
    }

    uint32_t m_pathMtu;
    uint32_t m_expectedMtu;
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * ACK frequency (msquic): the sender asks the peer to tolerate more ack-eliciting packets when its
 * flushes are limited by scheduling (more than 40 datagrams), and the frames survive a round trip.
 */
class QuicAckFrequencyTestCase : public TestCase
{
  public:
    QuicAckFrequencyTestCase()
        : TestCase("ACK_FREQUENCY: frame round trip and tolerance update")
    {
    }

  private:
    void DoRun() override
    {
        QuicSubheader sub = QuicSubheader::CreateAckFrequency(3, 41, 25000, 1);
        Ptr<Packet> p = Create<Packet>(0);
        p->AddHeader(sub);
        QuicSubheader out;
        p->RemoveHeader(out);
        NS_TEST_ASSERT_MSG_EQ(out.IsAckFrequency(), true, "frame type");
        NS_TEST_ASSERT_MSG_EQ(out.GetAckFreqSequence(), 3u, "sequence");
        NS_TEST_ASSERT_MSG_EQ(out.GetAckFreqThreshold(), 41u, "threshold");
        NS_TEST_ASSERT_MSG_EQ(out.GetAckFreqMaxDelayUs(), 25000u, "max ack delay");
        NS_TEST_ASSERT_MSG_EQ(out.GetAckFreqReordering(), 1u, "reordering");

        Ptr<Packet> q = Create<Packet>(0);
        q->AddHeader(QuicSubheader::CreateImmediateAck());
        QuicSubheader out2;
        q->RemoveHeader(out2);
        NS_TEST_ASSERT_MSG_EQ(out2.IsImmediateAck(), true, "immediate ack");

        // end to end: a fast path lets the sender flush more than 40 datagrams at once
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
        p2p.SetChannelAttribute("Delay", StringValue("20ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.7.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicAckFrequencyTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Stop(Seconds(6));
        Simulator::Run();
        uint8_t asked = DynamicCast<QuicSocketBase>(m_server)->GetPeerAckTolerance();
        uint8_t applied = DynamicCast<QuicSocketBase>(m_client)->GetAckTolerance();
        Simulator::Destroy();
        NS_TEST_ASSERT_MSG_EQ((uint32_t)asked, 41u, "the sender should ask for tolerance 41");
        NS_TEST_ASSERT_MSG_EQ((uint32_t)applied,
                              41u,
                              "the receiver should apply the requested tolerance");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
        for (uint32_t off = 0; off < 20000000; off += 1000)
        {
            if (s->Send(Create<Packet>(1000), 1) < 0)
            {
                break;
            }
        }
    }

    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * Stateless reset (msquic): when the server lost the state of a connection, a packet from the
 * client is answered with a reset that carries the token announced in the transport parameters, and
 * the client closes at once instead of waiting for the disconnect timeout.
 */
class QuicStatelessResetTestCase : public TestCase
{
  public:
    QuicStatelessResetTestCase()
        : TestCase("stateless reset closes a connection the server forgot")
    {
    }

  private:
    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.8.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicStatelessResetTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetCloseCallbacks(MakeNullCallback<void, Ptr<Socket>>(),
                                    MakeCallback(&QuicStatelessResetTestCase::ClientError, this));
        Ptr<QuicL4Protocol> serverL4 = nodes.Get(0)->GetObject<QuicL4Protocol>();
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        // the server forgets the connection silently (a restart), then the client sends something
        Simulator::Schedule(Seconds(1.0), [this, serverL4]() {
            serverL4->RemoveSocket(DynamicCast<QuicSocketBase>(m_server));
        });
        Simulator::Schedule(Seconds(1.5), [this]() { m_client->Send(Create<Packet>(200), 0); });
        Simulator::Stop(Seconds(30));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_errorAt.IsStrictlyPositive(),
                              true,
                              "the client never learned of the reset");
        NS_TEST_ASSERT_MSG_GT(m_errorAt, Seconds(1.5), "closed before the client sent anything");
        NS_TEST_ASSERT_MSG_LT(m_errorAt,
                              Seconds(2.0),
                              "the reset should arrive within about an RTT");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
    }

    void ClientError(Ptr<Socket>)
    {
        m_errorAt = Simulator::Now();
    }

    Time m_errorAt{Seconds(0)};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * Stream ids and limits (RFC 9000 s2.1, s4.6; msquic stream_set.c): ids carry the initiator and the
 * direction, the peer's limit stops new streams (STREAMS_BLOCKED) until a MAX_STREAMS frame raises
 * it.
 */
class QuicStreamLimitsTestCase : public TestCase
{
  public:
    QuicStreamLimitsTestCase()
        : TestCase("stream ids follow RFC 9000 and MAX_STREAMS raises the limit")
    {
    }

  private:
    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.9.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicStreamLimitsTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        // the client lets the server open only two bidirectional streams
        m_client->SetAttribute("MaxStreamIdBidi", UintegerValue(2));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1.0), [this]() { Probe(); });
        Simulator::Schedule(Seconds(1.5), [this]() {
            // a stream of the other side cannot be opened here; a server stream with the uni bit
            // can
            m_wrongSide = DynamicCast<QuicSocketBase>(m_server)->Send(Create<Packet>(10), 0);
            m_uni = DynamicCast<QuicSocketBase>(m_server)->Send(Create<Packet>(10), 3);
            // the client finished streams and allows one more
            DynamicCast<QuicSocketBase>(m_client)->GrantPeerStream(true);
        });
        Simulator::Schedule(Seconds(2.0), [this]() {
            m_afterGrant = DynamicCast<QuicSocketBase>(m_server)->Send(Create<Packet>(10), 9);
        });
        Simulator::Stop(Seconds(3));
        Simulator::Run();
        uint64_t serverLimit = DynamicCast<QuicSocketBase>(m_server)->GetPeerMaxStreams(true);
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_first, 10, "first server stream (id 1)");
        NS_TEST_ASSERT_MSG_EQ(m_second, 10, "second server stream (id 5)");
        NS_TEST_ASSERT_MSG_EQ(m_third, -1, "third stream (id 9) is beyond the peer limit of 2");
        NS_TEST_ASSERT_MSG_EQ(m_wrongSide, -1, "stream 0 belongs to the client");
        NS_TEST_ASSERT_MSG_EQ(m_uni, 10, "server-initiated unidirectional stream (id 3)");
        NS_TEST_ASSERT_MSG_EQ(serverLimit, 3u, "MAX_STREAMS raised the limit");
        NS_TEST_ASSERT_MSG_EQ(m_afterGrant, 10, "the third stream opens once the limit grew");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
    }

    void Probe()
    {
        Ptr<QuicSocketBase> srv = DynamicCast<QuicSocketBase>(m_server);
        m_first = srv->Send(Create<Packet>(10), 1);
        m_second = srv->Send(Create<Packet>(10), 5);
        m_third = srv->Send(Create<Packet>(10), 9);
    }

    int m_first{0}, m_second{0}, m_third{0}, m_wrongSide{0}, m_uni{0}, m_afterGrant{0};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * Stream credit (msquic QuicStreamSetReleaseStream): when a peer stream completes in both
 * directions the peer gets a new stream credit through MAX_STREAMS, so a limit of two streams does
 * not end the connection.
 */
class QuicStreamCreditTestCase : public TestCase
{
  public:
    QuicStreamCreditTestCase()
        : TestCase("finished peer streams return stream credit with MAX_STREAMS")
    {
    }

  private:
    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.10.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicStreamCreditTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetAttribute("MaxStreamIdBidi", UintegerValue(2));
        m_client->SetRecvCallback(MakeCallback(&QuicStreamCreditTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1.0), [this]() {
            Ptr<QuicSocketBase> srv = DynamicCast<QuicSocketBase>(m_server);
            for (uint32_t n = 1; n <= 2; ++n)
            {
                srv->Send(Create<Packet>(5000), ServerStreamId(n));
                srv->FinishStream(ServerStreamId(n));
            }
            m_blockedBefore = srv->Send(Create<Packet>(10), ServerStreamId(3));
        });
        Simulator::Schedule(Seconds(2.0), [this]() {
            m_openAfter =
                DynamicCast<QuicSocketBase>(m_server)->Send(Create<Packet>(10), ServerStreamId(3));
        });
        Simulator::Stop(Seconds(3));
        Simulator::Run();
        uint64_t limit = DynamicCast<QuicSocketBase>(m_server)->GetPeerMaxStreams(true);
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_rx[1], 5000u, "stream 1 data");
        NS_TEST_ASSERT_MSG_EQ(m_rx[2], 5000u, "stream 2 data");
        NS_TEST_ASSERT_MSG_EQ(m_blockedBefore, -1, "a third stream exceeds the limit of two");
        NS_TEST_ASSERT_MSG_EQ(limit, 4u, "each finished stream gave one credit");
        NS_TEST_ASSERT_MSG_EQ(m_openAfter, 10, "the third stream opens after the credit arrived");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            for (ByteTagIterator it = p->GetByteTagIterator(); it.HasNext();)
            {
                ByteTagIterator::Item item = it.Next();
                if (item.GetTypeId() != QuicStreamIdTag::GetTypeId())
                {
                    continue;
                }
                QuicStreamIdTag tag;
                item.GetTag(tag);
                m_rx[LogicalStream(tag.GetStreamId())] += item.GetEnd() - item.GetStart();
            }
        }
    }

    std::map<uint32_t, uint32_t> m_rx;
    int m_blockedBefore{0};
    int m_openAfter{0};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * Connection ids and migration (RFC 9000 s5.1, s9; msquic path.c): each side issues connection ids
 * up to the peer's limit; when the client moves to another address the server challenges the new
 * path, switches to it on the first non-probing packet and starts it from scratch (MTU, RTT,
 * congestion window), except that a port-only rebinding keeps the congestion state.
 */
class QuicMigrationTestCase : public TestCase
{
  public:
    QuicMigrationTestCase(std::string name, bool portOnly, bool serverForbids = false)
        : TestCase(name),
          m_portOnly(portOnly),
          m_serverForbids(serverForbids)
    {
    }

  private:
    static constexpr uint32_t kTotal = 4000000;

    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.11.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        // the client has a second address on the same interface (a WiFi to LTE style change)
        Ptr<Ipv4> clientIp = nodes.Get(1)->GetObject<Ipv4>();
        clientIp->AddAddress(
            1,
            Ipv4InterfaceAddress(Ipv4Address("10.9.11.77"), Ipv4Mask("255.255.255.0")));

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        if (m_serverForbids)
        {
            m_listen->SetAttribute("DisableActiveMigration", BooleanValue(true));
        }
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicMigrationTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicMigrationTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1.0), [this]() {
            Ptr<QuicSocketBase> srv = DynamicCast<QuicSocketBase>(m_server);
            m_cidsServer = srv->GetActiveSourceCids() * 10 + srv->GetActiveDestCids();
            m_cwndBefore = srv->GetCongestionWindowBytes();
            Address local = m_portOnly ? Address(InetSocketAddress(Ipv4Address("10.9.11.2"), 0))
                                       : Address(InetSocketAddress(Ipv4Address("10.9.11.77"), 0));
            m_moved = DynamicCast<QuicSocketBase>(m_client)->Migrate(local);
        });
        Simulator::Schedule(Seconds(1.12), [this]() {
            m_cwndAfter = DynamicCast<QuicSocketBase>(m_server)->GetCongestionWindowBytes();
        });
        Simulator::Stop(Seconds(20));
        Simulator::Run();
        Ptr<QuicSocketBase> srv = DynamicCast<QuicSocketBase>(m_server);
        Ipv4Address remote = InetSocketAddress::ConvertFrom(srv->GetActiveRemote()).GetIpv4();
        bool validated = srv->IsActivePathValidated();
        uint32_t seg = srv->GetPathSegmentSize();
        Simulator::Destroy();

        if (m_serverForbids)
        {
            // RFC 9000 s18.2: the server announced disable_active_migration, so the client stays
            // where it is
            NS_TEST_ASSERT_MSG_EQ(
                m_moved,
                false,
                "the client migrated although the server disabled active migration");
            NS_TEST_ASSERT_MSG_EQ(m_rx, kTotal, "data lost");
            NS_TEST_ASSERT_MSG_EQ(remote == Ipv4Address("10.9.11.2"), true, "the path changed");
            return;
        }
        NS_TEST_ASSERT_MSG_EQ(m_cidsServer,
                              44u,
                              "each side issues connection ids up to the peer limit of 4");
        NS_TEST_ASSERT_MSG_EQ(m_moved, true, "the client could not move");
        NS_TEST_ASSERT_MSG_EQ(m_rx, kTotal, "data lost across the migration");
        if (!m_portOnly)
        {
            NS_TEST_ASSERT_MSG_EQ(remote == Ipv4Address("10.9.11.77"),
                                  true,
                                  "the server did not follow the client");
            NS_TEST_ASSERT_MSG_LT(m_cwndAfter,
                                  m_cwndBefore,
                                  "a new path must restart congestion control");
        }
        else
        {
            NS_TEST_ASSERT_MSG_EQ(remote == Ipv4Address("10.9.11.2"), true, "same address");
            NS_TEST_ASSERT_MSG_GT(m_cwndAfter,
                                  m_cwndBefore / 2,
                                  "a port-only rebind keeps the congestion window");
        }
        NS_TEST_ASSERT_MSG_EQ(validated, true, "the new path was never validated");
        NS_TEST_ASSERT_MSG_EQ(seg, 1459u, "the new path did not rediscover its MTU");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
        for (uint32_t off = 0; off < kTotal; off += 1000)
        {
            s->Send(Create<Packet>(1000), ServerStreamId(1));
        }
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            m_rx += p->GetSize();
        }
    }

    bool m_portOnly;
    bool m_serverForbids;
    uint32_t m_rx{0};
    uint32_t m_cwndBefore{0};
    uint32_t m_cwndAfter{0};
    uint32_t m_cidsServer{0};
    bool m_moved{false};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * Receive error model that drops the first `count` QUIC packets sent to `dst` whose first frame is
 * `frameType`. It parses the packet as the device receives it: PPP, IPv4, UDP, QUIC short header,
 * first frame.
 */
class QuicFrameDropper : public ErrorModel
{
  public:
    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::QuicFrameDropper")
                                .SetParent<ErrorModel>()
                                .AddConstructor<QuicFrameDropper>();
        return tid;
    }

    void Configure(Ipv4Address dst, uint8_t frameType, uint32_t count)
    {
        m_dst = dst;
        m_frameType = frameType;
        m_count = count;
    }

    uint32_t Dropped(void) const
    {
        return m_dropped;
    }

  private:
    bool DoCorrupt(Ptr<Packet> p) override
    {
        if (m_dropped >= m_count)
        {
            return false;
        }
        Ptr<Packet> c = p->Copy();
        PppHeader ppp;
        c->RemoveHeader(ppp);
        Ipv4Header ip;
        c->RemoveHeader(ip);
        if (ip.GetProtocol() != 17 || ip.GetDestination() != m_dst)
        {
            return false;
        }
        UdpHeader udp;
        c->RemoveHeader(udp);
        QuicHeader quic;
        c->RemoveHeader(quic);
        if (!quic.IsShort() || c->GetSize() == 0)
        {
            return false;
        }
        QuicSubheader frame;
        c->RemoveHeader(frame);
        if (frame.GetFrameType() != m_frameType)
        {
            return false;
        }
        ++m_dropped;
        return true;
    }

    void DoReset(void) override
    {
    }

    Ipv4Address m_dst;
    uint8_t m_frameType{0};
    uint32_t m_count{0};
    uint32_t m_dropped{0};
};

/**
 * Path validation survives losses (RFC 9000 s8.2, s9.3). The client moves to another address while
 * the server has nothing in flight, so no ACK from the client replenishes the server's
 * anti-amplification allowance on the new path (three times what the client sent there). The server
 * then has to repeat a lost PATH_CHALLENGE (or answer again when the PATH_RESPONSE was lost) with
 * what it kept of that allowance: a first challenge that spends all of it leaves the path
 * unvalidated, the server blocked, and the connection is closed when the validation times out.
 * After the move the server writes again, which only gets through once the new path is validated.
 */
class QuicPathValidationLossTestCase : public TestCase
{
  public:
    QuicPathValidationLossTestCase(std::string name, uint8_t droppedFrame, uint32_t drops)
        : TestCase(name),
          m_droppedFrame(droppedFrame),
          m_drops(drops)
    {
    }

  private:
    static constexpr uint32_t kFirst = 100000;  //!< written when the connection opens
    static constexpr uint32_t kSecond = 100000; //!< written after the client moved

    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.12.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        Ptr<Ipv4> clientIp = nodes.Get(1)->GetObject<Ipv4>();
        clientIp->AddAddress(
            1,
            Ipv4InterfaceAddress(Ipv4Address("10.9.12.77"), Ipv4Mask("255.255.255.0")));

        // the challenge goes to the client's new address, the response back to the server
        Ptr<QuicFrameDropper> dropper = CreateObject<QuicFrameDropper>();
        bool challenge = m_droppedFrame == QuicSubheader::PATH_CHALLENGE;
        dropper->Configure(challenge ? Ipv4Address("10.9.12.77") : ifs.GetAddress(0),
                           m_droppedFrame,
                           m_drops);
        dev.Get(challenge ? 1 : 0)->SetAttribute("ReceiveErrorModel", PointerValue(dropper));

        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicPathValidationLossTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicPathValidationLossTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1.0), [this]() {
            Ptr<QuicSocketBase> c = DynamicCast<QuicSocketBase>(m_client);
            c->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(&QuicPathValidationLossTestCase::OnClientTx, this));
            m_moved = c->Migrate(InetSocketAddress(Ipv4Address("10.9.12.77"), 0));
        });
        Simulator::Schedule(Seconds(1.5), [this]() { Write(kSecond); });
        Simulator::Stop(Seconds(15));
        Simulator::Run();
        Ptr<QuicSocketBase> srv = DynamicCast<QuicSocketBase>(m_server);
        // (a server that closed the connection has dropped its paths: no remote address any more)
        Address activeRemote = srv->GetActiveRemote();
        Ipv4Address remote = InetSocketAddress::IsMatchingType(activeRemote)
                                 ? InetSocketAddress::ConvertFrom(activeRemote).GetIpv4()
                                 : Ipv4Address();
        bool validated = srv->IsActivePathValidated();
        bool open = srv->GetSocketState() == QuicSocketBase::OPEN;
        uint32_t dropped = dropper->Dropped();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_moved, true, "the client could not move");
        NS_TEST_ASSERT_MSG_GT(
            m_firstProbe,
            (uint32_t)QuicSocketBase::MIN_INITIAL_PACKET_SIZE - 1,
            "the first packet on the new path is "
                << m_firstProbe
                << " bytes: too small to give the server room to repeat a challenge");
        NS_TEST_ASSERT_MSG_EQ(dropped, m_drops, "the loss was not injected");
        NS_TEST_ASSERT_MSG_EQ(open,
                              true,
                              "the server closed the connection when the path validation failed");
        NS_TEST_ASSERT_MSG_EQ(remote == Ipv4Address("10.9.12.77"),
                              true,
                              "the server did not follow the client");
        NS_TEST_ASSERT_MSG_EQ(validated, true, "the new path was never validated");
        NS_TEST_ASSERT_MSG_EQ(m_rx, kFirst + kSecond, "data written after the move did not arrive");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
        Write(kFirst);
    }

    // the first packet the client sends after it moved: the probe of the new path
    void OnClientTx(Ptr<const Packet> p, const QuicHeader& h, Ptr<const QuicSocketBase>)
    {
        if (m_firstProbe == 0)
        {
            m_firstProbe = p->GetSize() + h.GetSerializedSize();
        }
    }

    void Write(uint32_t bytes)
    {
        for (uint32_t off = 0; off < bytes; off += 1000)
        {
            m_server->Send(Create<Packet>(1000), ServerStreamId(1));
        }
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            m_rx += p->GetSize();
        }
    }

    uint8_t m_droppedFrame;
    uint32_t m_drops;
    uint32_t m_rx{0};
    uint32_t m_firstProbe{0};
    bool m_moved{false};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

/**
 * After 20 s without sending, msquic switches to a new destination connection id
 * (DestCidUpdateIdleTimeoutMs); the peer answers by switching its own, and the retired ids go back
 * with RETIRE_CONNECTION_ID.
 */
class QuicDestCidUpdateTestCase : public TestCase
{
  public:
    QuicDestCidUpdateTestCase()
        : TestCase("connection id changes after an idle period")
    {
    }

  private:
    void DoRun() override
    {
        StreamDefaults();
        NodeContainer nodes;
        nodes.Create(2);
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("10ms"));
        NetDeviceContainer dev = p2p.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        QuicHelper quic;
        quic.InstallQuic(nodes);
        Ipv4AddressHelper ip;
        ip.SetBase("10.9.12.0", "255.255.255.0");
        Ipv4InterfaceContainer ifs = ip.Assign(dev);
        TypeId tid = QuicSocketFactory::GetTypeId();
        m_listen = Socket::CreateSocket(nodes.Get(0), tid);
        m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
        m_listen->Listen();
        m_listen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&QuicDestCidUpdateTestCase::Accept, this));
        m_client = Socket::CreateSocket(nodes.Get(1), tid);
        m_client->SetRecvCallback(MakeCallback(&QuicDestCidUpdateTestCase::Read, this));
        Simulator::Schedule(Seconds(0.1), [this, &ifs]() {
            m_client->Connect(InetSocketAddress(ifs.GetAddress(0), 4433));
        });
        Simulator::Schedule(Seconds(1.0), [this]() {
            m_cidBefore = DynamicCast<QuicSocketBase>(m_client)->GetDestCid();
            m_serverCidBefore = DynamicCast<QuicSocketBase>(m_server)->GetDestCid();
        });
        Simulator::Schedule(Seconds(25.0), [this]() {
            DynamicCast<QuicSocketBase>(m_server)->Send(Create<Packet>(100), ServerStreamId(1));
        });
        Simulator::Stop(Seconds(27));
        Simulator::Run();
        Ptr<QuicSocketBase> cli = DynamicCast<QuicSocketBase>(m_client);
        Ptr<QuicSocketBase> srv = DynamicCast<QuicSocketBase>(m_server);
        uint64_t cliAfter = cli->GetDestCid();
        uint64_t srvAfter = srv->GetDestCid();
        uint32_t cliActive = cli->GetActiveDestCids();
        uint32_t srvActive = srv->GetActiveSourceCids();
        Simulator::Destroy();

        NS_TEST_ASSERT_MSG_EQ(m_rx, 100u, "data after the pause");
        NS_TEST_ASSERT_MSG_EQ(srvAfter != m_serverCidBefore,
                              true,
                              "the server did not change its destination id");
        NS_TEST_ASSERT_MSG_EQ(cliAfter != m_cidBefore,
                              true,
                              "the client did not answer with a change of its own");
        // the retired ids were replaced: the endpoints are back at the limit of four
        NS_TEST_ASSERT_MSG_EQ(cliActive, 4u, "the client keeps four usable ids of the peer");
        NS_TEST_ASSERT_MSG_EQ(srvActive,
                              4u,
                              "the server issued replacements for the ids that were retired");
    }

    void Accept(Ptr<Socket> s, const Address&)
    {
        m_server = s;
        s->Send(Create<Packet>(100), ServerStreamId(1));
    }

    void Read(Ptr<Socket> s)
    {
        Ptr<Packet> p;
        while ((p = s->Recv()) && p->GetSize() > 0)
        {
            if (Simulator::Now() > Seconds(20))
            {
                m_rx += p->GetSize();
            }
        }
    }

    uint32_t m_rx{0};
    uint64_t m_cidBefore{0};
    uint64_t m_serverCidBefore{0};
    Ptr<Socket> m_listen;
    Ptr<Socket> m_server;
    Ptr<Socket> m_client;
};

class QuicTestSuite : public TestSuite
{
  public:
    QuicTestSuite();
};

QuicTestSuite::QuicTestSuite()
    : TestSuite("quic", Type::UNIT)
{
    // RFC 9000 §19 — Frame types
    AddTestCase(new QuicFrameTypeValuesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicFrameTypeAliasesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicStreamFrameEncodingTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicIsStreamTestCase, TestCase::Duration::QUICK);

    // RFC 9000 §20 — Error codes
    AddTestCase(new QuicTransportErrorCodeValuesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicErrorCodeAliasesTestCase, TestCase::Duration::QUICK);

    // RFC 9002 §5.3 — kInitialRtt
    AddTestCase(new QuicInitialRttTestCase, TestCase::Duration::QUICK);

    // RFC 9002 §7.6.3 — Persistent congestion
    AddTestCase(new QuicPersistentCongestionThresholdTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicPersistentCongestionDetectionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicNoPersistentCongestionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicPersistentCongestionNoRttTestCase, TestCase::Duration::QUICK);

    // RFC 9000 §17.3.1 — Spin Bit
    AddTestCase(new QuicSpinBitTestCase, TestCase::Duration::QUICK);

    // RFC 9000 §18.2 — Transport Parameters
    AddTestCase(new QuicActiveConnIdLimitTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicStatelessResetTokenTestCase, TestCase::Duration::QUICK);

    // RFC 9000 §20 — FRAME_ENCODING_ERROR
    AddTestCase(new QuicFrameEncodingErrorTestCase, TestCase::Duration::QUICK);

    // End-to-end behaviour
    AddTestCase(new QuicEndToEndTestCase("end-to-end, no loss", 0.0, 65536, 16777216),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicEndToEndTestCase("end-to-end, 2% loss", 0.02, 65536, 16777216),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicEndToEndTestCase("end-to-end, 5% loss", 0.05, 65536, 16777216),
                TestCase::Duration::QUICK);
    AddTestCase(
        new QuicEndToEndTestCase("end-to-end, small flow-control windows", 0.0, 8192, 24576),
        TestCase::Duration::QUICK);
    AddTestCase(
        new QuicEndToEndTestCase("end-to-end, small windows and 2% loss", 0.02, 8192, 24576),
        TestCase::Duration::QUICK);
    AddTestCase(new QuicEndToEndTestCase("end-to-end, STOP_SENDING resets stream 2",
                                         0.0,
                                         65536,
                                         16777216,
                                         2),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicReorderingTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicCubicEventsTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicAckFrequencyTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicStatelessResetTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicStreamLimitsTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicStreamCreditTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicDestCidUpdateTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicMigrationTestCase("migration to a new address restarts the path", false),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicMigrationTestCase("port-only rebinding keeps the congestion window", true),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicMigrationTestCase(
                    "a server that announces disable_active_migration is not migrated",
                    false,
                    true),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicPathValidationLossTestCase("path validation, nothing lost",
                                                   QuicSubheader::PATH_CHALLENGE,
                                                   0),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicPathValidationLossTestCase(
                    "path validation survives the loss of the first PATH_CHALLENGE",
                    QuicSubheader::PATH_CHALLENGE,
                    1),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicPathValidationLossTestCase(
                    "path validation survives the loss of the first PATH_RESPONSE",
                    QuicSubheader::PATH_RESPONSE,
                    1),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicPathValidationLossTestCase(
                    "path validation survives the loss of two PATH_CHALLENGEs in a row",
                    QuicSubheader::PATH_CHALLENGE,
                    2),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicPathValidationLossTestCase(
                    "path validation survives the loss of three PATH_CHALLENGEs in a row",
                    QuicSubheader::PATH_CHALLENGE,
                    3),
                TestCase::Duration::QUICK);
    AddTestCase(new QuicMtuDiscoveryTestCase("path MTU discovery reaches 1500", 1500, 1500),
                TestCase::Duration::QUICK);
    AddTestCase(
        new QuicMtuDiscoveryTestCase("path MTU discovery stops below a 1400 byte path", 1400, 1368),
        TestCase::Duration::QUICK);
    AddTestCase(new QuicIdleTimeoutTestCase, TestCase::Duration::QUICK);
    AddTestCase(
        new QuicBlackoutTestCase("handshake survives a 1 s outage", Seconds(1), Seconds(0.05)),
        TestCase::Duration::QUICK);
    AddTestCase(new QuicStreamFifoSchedulerTestCase, TestCase::Duration::QUICK);
    AddTestCase(new QuicRoundRobinSchedulerTestCase, TestCase::Duration::QUICK);
    AddTestCase(
        new QuicStreamPriorityTestCase("stream priority: late small stream goes first", true),
        TestCase::Duration::QUICK);
    AddTestCase(new QuicBlackoutTestCase("blackout of 3 s is survived", Seconds(3)),
                TestCase::Duration::QUICK);
    AddTestCase(
        new QuicBlackoutTestCase("permanent blackout closes after DisconnectTimeout", Seconds(0)),
        TestCase::Duration::QUICK);
    AddTestCase(new QuicEndToEndTestCase("end-to-end, STOP_SENDING under 2% loss",
                                         0.02,
                                         65536,
                                         16777216,
                                         2),
                TestCase::Duration::QUICK);
}

static QuicTestSuite sQuicTestSuite;
