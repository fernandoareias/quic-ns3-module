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

#include "../model/quic-subheader.h"
#include "../model/quic-socket-base.h"
#include "../model/quic-congestion-ops.h"
#include "../model/quic-socket-tx-buffer.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/test.h"

using namespace ns3;

// ---------------------------------------------------------------------------
// §1  RFC 9000 §19 — Frame type wire values
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * Verifica que todos os TypeFrame_t têm os valores wire definidos pela RFC 9000 §19.
 */
class QuicFrameTypeValuesTestCase : public TestCase
{
public:
  QuicFrameTypeValuesTestCase ()
    : TestCase ("RFC 9000 §19 — frame type wire values match spec")
  {}

private:
  void DoRun () override
  {
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::PADDING,              0x00, "PADDING");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::PING,                 0x01, "PING");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::ACK,                  0x02, "ACK");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::ACK_ECN,              0x03, "ACK_ECN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::RESET_STREAM,         0x04, "RESET_STREAM");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STOP_SENDING,         0x05, "STOP_SENDING");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CRYPTO,               0x06, "CRYPTO");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::NEW_TOKEN,            0x07, "NEW_TOKEN");

    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM,               0x08, "STREAM");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_FIN,           0x09, "STREAM_FIN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_LEN,           0x0a, "STREAM_LEN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_LEN_FIN,       0x0b, "STREAM_LEN_FIN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_OFF,           0x0c, "STREAM_OFF");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_OFF_FIN,       0x0d, "STREAM_OFF_FIN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_OFF_LEN,       0x0e, "STREAM_OFF_LEN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_OFF_LEN_FIN,   0x0f, "STREAM_OFF_LEN_FIN");

    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::MAX_DATA,             0x10, "MAX_DATA");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::MAX_STREAM_DATA,      0x11, "MAX_STREAM_DATA");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::MAX_STREAMS_BIDI,     0x12, "MAX_STREAMS_BIDI");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::MAX_STREAMS_UNI,      0x13, "MAX_STREAMS_UNI");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::DATA_BLOCKED,         0x14, "DATA_BLOCKED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_DATA_BLOCKED,  0x15, "STREAM_DATA_BLOCKED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAMS_BLOCKED_BIDI, 0x16, "STREAMS_BLOCKED_BIDI");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAMS_BLOCKED_UNI,  0x17, "STREAMS_BLOCKED_UNI");

    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::NEW_CONNECTION_ID,    0x18, "NEW_CONNECTION_ID");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::RETIRE_CONNECTION_ID, 0x19, "RETIRE_CONNECTION_ID");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::PATH_CHALLENGE,       0x1a, "PATH_CHALLENGE");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::PATH_RESPONSE,        0x1b, "PATH_RESPONSE");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CONNECTION_CLOSE,     0x1c, "CONNECTION_CLOSE");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CONNECTION_CLOSE_APP, 0x1d, "CONNECTION_CLOSE_APP");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::HANDSHAKE_DONE,       0x1e, "HANDSHAKE_DONE");
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
  QuicFrameTypeAliasesTestCase ()
    : TestCase ("RFC 9000 §19 — backward-compat frame type aliases resolve to RFC values")
  {}

private:
  void DoRun () override
  {
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::RST_STREAM,        0x04, "RST_STREAM -> RESET_STREAM");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::APPLICATION_CLOSE, 0x1d, "APPLICATION_CLOSE -> CONNECTION_CLOSE_APP");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::MAX_STREAM_ID,     0x12, "MAX_STREAM_ID -> MAX_STREAMS_BIDI");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::BLOCKED,           0x14, "BLOCKED -> DATA_BLOCKED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_BLOCKED,    0x15, "STREAM_BLOCKED -> STREAM_DATA_BLOCKED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_ID_BLOCKED, 0x16, "STREAM_ID_BLOCKED -> STREAMS_BLOCKED_BIDI");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM000,         0x08, "STREAM000 -> STREAM");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM001,         0x09, "STREAM001 -> STREAM_FIN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM010,         0x0a, "STREAM010 -> STREAM_LEN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM011,         0x0b, "STREAM011 -> STREAM_LEN_FIN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM100,         0x0c, "STREAM100 -> STREAM_OFF");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM101,         0x0d, "STREAM101 -> STREAM_OFF_FIN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM110,         0x0e, "STREAM110 -> STREAM_OFF_LEN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM111,         0x0f, "STREAM111 -> STREAM_OFF_LEN_FIN");
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
  QuicTransportErrorCodeValuesTestCase ()
    : TestCase ("RFC 9000 §20 — transport error code wire values match spec")
  {}

private:
  void DoRun () override
  {
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::NO_ERROR,                  0x00, "NO_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::INTERNAL_ERROR,            0x01, "INTERNAL_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CONNECTION_REFUSED,        0x02, "CONNECTION_REFUSED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::FLOW_CONTROL_ERROR,        0x03, "FLOW_CONTROL_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_LIMIT_ERROR,        0x04, "STREAM_LIMIT_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_STATE_ERROR,        0x05, "STREAM_STATE_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::FINAL_SIZE_ERROR,          0x06, "FINAL_SIZE_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::FRAME_ENCODING_ERROR,      0x07, "FRAME_ENCODING_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::TRANSPORT_PARAMETER_ERROR, 0x08, "TRANSPORT_PARAMETER_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CONNECTION_ID_LIMIT_ERROR, 0x09, "CONNECTION_ID_LIMIT_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::PROTOCOL_VIOLATION,        0x0a, "PROTOCOL_VIOLATION");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::INVALID_TOKEN,             0x0b, "INVALID_TOKEN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::APPLICATION_ERROR,         0x0c, "APPLICATION_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CRYPTO_BUFFER_EXCEEDED,    0x0d, "CRYPTO_BUFFER_EXCEEDED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::KEY_UPDATE_ERROR,          0x0e, "KEY_UPDATE_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::AEAD_LIMIT_REACHED,        0x0f, "AEAD_LIMIT_REACHED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::NO_VIABLE_PATH,            0x10, "NO_VIABLE_PATH");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::CRYPTO_ERROR,              0x100, "CRYPTO_ERROR");
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
  QuicErrorCodeAliasesTestCase ()
    : TestCase ("RFC 9000 §20 — backward-compat error code aliases resolve to RFC values")
  {}

private:
  void DoRun () override
  {
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::SERVER_BUSY,               0x02, "SERVER_BUSY -> CONNECTION_REFUSED");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::STREAM_ID_ERROR,           0x04, "STREAM_ID_ERROR -> STREAM_LIMIT_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::FINAL_OFFSET_ERROR,        0x06, "FINAL_OFFSET_ERROR -> FINAL_SIZE_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::FRAME_FORMAT_ERROR,        0x07, "FRAME_FORMAT_ERROR -> FRAME_ENCODING_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::VERSION_NEGOTIATION_ERROR, 0x09, "VERSION_NEGOTIATION_ERROR -> CONNECTION_ID_LIMIT_ERROR");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::UNSOLICITED_PATH_ERROR,    0x0b, "UNSOLICITED_PATH_ERROR -> INVALID_TOKEN");
    NS_TEST_ASSERT_MSG_EQ ((int)QuicSubheader::FRAME_ERROR,               0x100, "FRAME_ERROR -> CRYPTO_ERROR");
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
  QuicStreamFrameEncodingTestCase ()
    : TestCase ("RFC 9000 §19.8 — STREAM frame type byte encoding (base=0x08)")
  {}

private:
  void DoRun () override
  {
    // Sem flags: tipo deve ser 0x08
    QuicSubheader s000 = QuicSubheader::CreateStreamSubHeader (1, 0, 100, false, false, false);
    NS_TEST_ASSERT_MSG_EQ ((int)s000.GetFrameType (), 0x08, "STREAM no flags");

    // FIN apenas: 0x08 | 0x01 = 0x09
    QuicSubheader s001 = QuicSubheader::CreateStreamSubHeader (1, 0, 100, false, false, true);
    NS_TEST_ASSERT_MSG_EQ ((int)s001.GetFrameType (), 0x09, "STREAM FIN");

    // LEN apenas: 0x08 | 0x02 = 0x0a
    QuicSubheader s010 = QuicSubheader::CreateStreamSubHeader (1, 0, 100, false, true, false);
    NS_TEST_ASSERT_MSG_EQ ((int)s010.GetFrameType (), 0x0a, "STREAM LEN");

    // LEN+FIN: 0x08 | 0x02 | 0x01 = 0x0b
    QuicSubheader s011 = QuicSubheader::CreateStreamSubHeader (1, 0, 100, false, true, true);
    NS_TEST_ASSERT_MSG_EQ ((int)s011.GetFrameType (), 0x0b, "STREAM LEN+FIN");

    // OFF apenas: 0x08 | 0x04 = 0x0c
    QuicSubheader s100 = QuicSubheader::CreateStreamSubHeader (1, 10, 100, true, false, false);
    NS_TEST_ASSERT_MSG_EQ ((int)s100.GetFrameType (), 0x0c, "STREAM OFF");

    // OFF+FIN: 0x08 | 0x04 | 0x01 = 0x0d
    QuicSubheader s101 = QuicSubheader::CreateStreamSubHeader (1, 10, 100, true, false, true);
    NS_TEST_ASSERT_MSG_EQ ((int)s101.GetFrameType (), 0x0d, "STREAM OFF+FIN");

    // OFF+LEN: 0x08 | 0x04 | 0x02 = 0x0e
    QuicSubheader s110 = QuicSubheader::CreateStreamSubHeader (1, 10, 100, true, true, false);
    NS_TEST_ASSERT_MSG_EQ ((int)s110.GetFrameType (), 0x0e, "STREAM OFF+LEN");

    // OFF+LEN+FIN: 0x08 | 0x04 | 0x02 | 0x01 = 0x0f
    QuicSubheader s111 = QuicSubheader::CreateStreamSubHeader (1, 10, 100, true, true, true);
    NS_TEST_ASSERT_MSG_EQ ((int)s111.GetFrameType (), 0x0f, "STREAM OFF+LEN+FIN");
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
  QuicIsStreamTestCase ()
    : TestCase ("RFC 9000 §19.8 — IsStream() range [0x08, 0x0f]")
  {}

private:
  void DoRun () override
  {
    // Todos os 8 tipos STREAM devem retornar IsStream() == true
    QuicSubheader::TypeFrame_t streamTypes[] = {
      QuicSubheader::STREAM,
      QuicSubheader::STREAM_FIN,
      QuicSubheader::STREAM_LEN,
      QuicSubheader::STREAM_LEN_FIN,
      QuicSubheader::STREAM_OFF,
      QuicSubheader::STREAM_OFF_FIN,
      QuicSubheader::STREAM_OFF_LEN,
      QuicSubheader::STREAM_OFF_LEN_FIN
    };
    for (auto ft : streamTypes)
      {
        QuicSubheader sh = QuicSubheader::CreateStreamSubHeader (1, 0, 10);
        sh.SetFrameType (ft);
        NS_TEST_ASSERT_MSG_EQ (sh.IsStream (), true,
                               "IsStream() deve ser true para 0x" << std::hex << (int)ft);
      }

    // Tipos não-STREAM devem retornar false
    QuicSubheader::TypeFrame_t nonStreamTypes[] = {
      QuicSubheader::PADDING,
      QuicSubheader::PING,
      QuicSubheader::ACK,
      QuicSubheader::RESET_STREAM,
      QuicSubheader::MAX_DATA,
      QuicSubheader::CONNECTION_CLOSE,
      QuicSubheader::HANDSHAKE_DONE
    };
    for (auto ft : nonStreamTypes)
      {
        QuicSubheader sh;
        sh.SetFrameType (ft);
        NS_TEST_ASSERT_MSG_EQ (sh.IsStream (), false,
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
  QuicInitialRttTestCase ()
    : TestCase ("RFC 9002 §5.3 — kDefaultInitialRtt == 333 ms")
  {}

private:
  void DoRun () override
  {
    QuicSocketState tcb;
    NS_TEST_ASSERT_MSG_EQ (tcb.m_kDefaultInitialRtt, MilliSeconds (333),
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
  QuicPersistentCongestionThresholdTestCase ()
    : TestCase ("RFC 9002 §7.6.3 — kPersistentCongestionThreshold == 3")
  {}

private:
  void DoRun () override
  {
    QuicSocketState tcb;
    NS_TEST_ASSERT_MSG_EQ (tcb.m_kPersistentCongestionThreshold, (uint32_t)3,
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
  QuicPersistentCongestionDetectionTestCase ()
    : TestCase ("RFC 9002 §7.6.3 — persistent congestion collapses cwnd to minimum")
  {}

private:
  void DoRun () override
  {
    Simulator::Run ();

    Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState> ();

    // Configura RTT estimado: srtt=50ms, rttvar=10ms, maxAckDelay=0
    tcb->m_smoothedRtt = MilliSeconds (50);
    tcb->m_rttVar      = MilliSeconds (10);
    tcb->m_latestRtt   = MilliSeconds (50);
    tcb->m_maxAckDelay = Seconds (0);

    // persistent congestion duration = (50 + max(4*10, 1) + 0) * 3
    //                                = (50 + 40) * 3 = 270 ms
    Time persistentDuration = MilliSeconds (270);

    // Cwnd inicial grande para confirmar que foi colapsado
    tcb->m_cWnd         = 100000;
    tcb->m_ssThresh     = 100000;
    uint32_t minWin     = tcb->m_kMinimumWindow;

    // Cria 2 pacotes perdidos cujo span (300 ms) > persistentDuration (270 ms)
    Ptr<Packet> pkt = Create<Packet> (500);

    Ptr<QuicSocketTxItem> p1 = CreateObject<QuicSocketTxItem> ();
    p1->m_packet       = pkt;
    p1->m_packetNumber = SequenceNumber32 (1);
    p1->m_lastSent     = MilliSeconds (0);
    p1->m_lost         = true;

    Ptr<QuicSocketTxItem> p2 = CreateObject<QuicSocketTxItem> ();
    p2->m_packet       = pkt;
    p2->m_packetNumber = SequenceNumber32 (2);
    p2->m_lastSent     = MilliSeconds (300);  // span = 300 ms > 270 ms
    p2->m_lost         = true;

    std::vector<Ptr<QuicSocketTxItem>> lostPackets = {p1, p2};

    // Chama OnPacketsLost
    QuicCongestionOps cc;
    cc.OnPacketsLost (tcb, lostPackets);

    // Persistent congestion deve ter colapsado cwnd para kMinimumWindow
    NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd, minWin,
                           "cwnd deve colapsar para kMinimumWindow ao detectar persistent congestion");
    NS_TEST_ASSERT_MSG_EQ (tcb->m_ssThresh, minWin,
                           "ssThresh deve colapsar para kMinimumWindow ao detectar persistent congestion");
    // min_rtt deve ser resetado para latest_rtt
    NS_TEST_ASSERT_MSG_EQ (tcb->m_minRtt, tcb->m_latestRtt,
                           "minRtt deve ser resetado para latestRtt apos persistent congestion");

    Simulator::Destroy ();
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
  QuicNoPersistentCongestionTestCase ()
    : TestCase ("RFC 9002 §7.6.3 — no persistent congestion when span < duration")
  {}

private:
  void DoRun () override
  {
    Simulator::Run ();

    Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState> ();

    tcb->m_smoothedRtt = MilliSeconds (50);
    tcb->m_rttVar      = MilliSeconds (10);
    tcb->m_latestRtt   = MilliSeconds (50);
    tcb->m_maxAckDelay = Seconds (0);

    // persistent congestion duration = 270 ms (ver §9 acima)
    uint32_t bigCwnd = 100000;
    tcb->m_cWnd      = bigCwnd;
    tcb->m_ssThresh  = bigCwnd;

    Ptr<Packet> pkt = Create<Packet> (500);

    Ptr<QuicSocketTxItem> p1 = CreateObject<QuicSocketTxItem> ();
    p1->m_packet       = pkt;
    p1->m_packetNumber = SequenceNumber32 (1);
    p1->m_lastSent     = MilliSeconds (0);
    p1->m_lost         = true;

    Ptr<QuicSocketTxItem> p2 = CreateObject<QuicSocketTxItem> ();
    p2->m_packet       = pkt;
    p2->m_packetNumber = SequenceNumber32 (2);
    p2->m_lastSent     = MilliSeconds (100);  // span = 100 ms < 270 ms
    p2->m_lost         = true;

    std::vector<Ptr<QuicSocketTxItem>> lostPackets = {p1, p2};

    QuicCongestionOps cc;
    cc.OnPacketsLost (tcb, lostPackets);

    // cwnd foi reduzido pelo recovery normal (×0.5), mas NÃO colapsado ao mínimo
    uint32_t minWin = tcb->m_kMinimumWindow;
    NS_TEST_ASSERT_MSG_GT (tcb->m_cWnd, minWin,
                           "cwnd nao deve colapsar para minimo quando span < persistent congestion duration");

    Simulator::Destroy ();
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
  QuicPersistentCongestionNoRttTestCase ()
    : TestCase ("RFC 9002 §7.6.3 — persistent congestion requires prior RTT sample")
  {}

private:
  void DoRun () override
  {
    Simulator::Run ();

    Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState> ();

    // Sem amostra de RTT (smoothedRtt = 0)
    tcb->m_smoothedRtt = Seconds (0);
    tcb->m_rttVar      = Seconds (0);
    tcb->m_latestRtt   = Seconds (0);
    tcb->m_maxAckDelay = Seconds (0);

    uint32_t bigCwnd = 100000;
    tcb->m_cWnd      = bigCwnd;
    tcb->m_ssThresh  = bigCwnd;

    Ptr<Packet> pkt = Create<Packet> (500);

    Ptr<QuicSocketTxItem> p1 = CreateObject<QuicSocketTxItem> ();
    p1->m_packet       = pkt;
    p1->m_packetNumber = SequenceNumber32 (1);
    p1->m_lastSent     = MilliSeconds (0);
    p1->m_lost         = true;

    Ptr<QuicSocketTxItem> p2 = CreateObject<QuicSocketTxItem> ();
    p2->m_packet       = pkt;
    p2->m_packetNumber = SequenceNumber32 (2);
    p2->m_lastSent     = Seconds (10);  // span enorme, mas sem RTT sample
    p2->m_lost         = true;

    std::vector<Ptr<QuicSocketTxItem>> lostPackets = {p1, p2};

    QuicCongestionOps cc;
    cc.OnPacketsLost (tcb, lostPackets);

    uint32_t minWin = tcb->m_kMinimumWindow;
    NS_TEST_ASSERT_MSG_GT (tcb->m_cWnd, minWin,
                           "persistent congestion nao deve disparar sem amostra previa de RTT");

    Simulator::Destroy ();
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
  QuicSpinBitTestCase ()
    : TestCase ("RFC 9000 s17.3.1 spin bit serialize and deserialize")
  {}

private:
  void DoRun () override
  {
    // Create short header with spin bit = 0
    QuicHeader h0 = QuicHeader::CreateShort (0xDEADBEEF, SequenceNumber32 (42), true, QuicHeader::PHASE_ZERO, false);
    NS_TEST_ASSERT_MSG_EQ (h0.GetSpinBit (), false, "spin bit 0 set");

    // Create short header with spin bit = 1
    QuicHeader h1 = QuicHeader::CreateShort (0xDEADBEEF, SequenceNumber32 (43), true, QuicHeader::PHASE_ZERO, true);
    NS_TEST_ASSERT_MSG_EQ (h1.GetSpinBit (), true, "spin bit 1 set");

    // Serialize h1 and deserialize — spin bit must round-trip
    uint32_t sz = h1.GetSerializedSize ();
    Buffer buf;
    buf.AddAtEnd (sz);
    Buffer::Iterator wit = buf.Begin ();
    h1.Serialize (wit);

    QuicHeader h2;
    Buffer::Iterator rit = buf.Begin ();
    h2.Deserialize (rit);

    NS_TEST_ASSERT_MSG_EQ (h2.GetSpinBit (), true, "spin bit round-trip");
    NS_TEST_ASSERT_MSG_EQ (h2.GetKeyPhaseBit (), false, "key phase round-trip after spin bit");
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
  QuicActiveConnIdLimitTestCase ()
    : TestCase ("RFC 9000 s18.2 active_connection_id_limit >= 2")
  {}

private:
  void DoRun () override
  {
    QuicTransportParameters tp;
    NS_TEST_ASSERT_MSG_EQ (tp.GetActiveConnectionIdLimit () >= 2, true,
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
  QuicStatelessResetTokenTestCase ()
    : TestCase ("RFC 9000 s18.2 stateless reset token round-trip")
  {}

private:
  void DoRun () override
  {
    QuicTransportParameters tp;
    tp.SetStatelessResetToken (0xDEADBEEFCAFEBABEULL, 0xFEEDFACECAFED00DULL);

    uint32_t sz = tp.GetSerializedSize ();
    Buffer buf;
    buf.AddAtEnd (sz);
    Buffer::Iterator wit = buf.Begin ();
    tp.Serialize (wit);

    QuicTransportParameters tp2;
    Buffer::Iterator rit = buf.Begin ();
    tp2.Deserialize (rit);

    NS_TEST_ASSERT_MSG_EQ (tp2.GetStatelessResetTokenHi (), 0xDEADBEEFCAFEBABEULL, "token hi");
    NS_TEST_ASSERT_MSG_EQ (tp2.GetStatelessResetTokenLo (), 0xFEEDFACECAFED00DULL, "token lo");
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
  QuicFrameEncodingErrorTestCase ()
    : TestCase ("RFC 9000 s20 FRAME_ENCODING_ERROR wire value")
  {}

private:
  void DoRun () override
  {
    NS_TEST_ASSERT_MSG_EQ (
      (int)QuicSubheader::TransportErrorCodes_t::FRAME_ENCODING_ERROR,
      0x07, "FRAME_ENCODING_ERROR must be 0x07 per RFC 9000 §20");
  }
};

// ---------------------------------------------------------------------------
// TestSuite
// ---------------------------------------------------------------------------

/**
 * @ingroup quic-tests
 * TestSuite para o módulo QUIC — RFC 9000 e RFC 9002
 */
class QuicTestSuite : public TestSuite
{
public:
  QuicTestSuite ();
};

QuicTestSuite::QuicTestSuite ()
  : TestSuite ("quic", Type::UNIT)
{
  // RFC 9000 §19 — Frame types
  AddTestCase (new QuicFrameTypeValuesTestCase,         TestCase::Duration::QUICK);
  AddTestCase (new QuicFrameTypeAliasesTestCase,        TestCase::Duration::QUICK);
  AddTestCase (new QuicStreamFrameEncodingTestCase,     TestCase::Duration::QUICK);
  AddTestCase (new QuicIsStreamTestCase,                TestCase::Duration::QUICK);

  // RFC 9000 §20 — Error codes
  AddTestCase (new QuicTransportErrorCodeValuesTestCase, TestCase::Duration::QUICK);
  AddTestCase (new QuicErrorCodeAliasesTestCase,         TestCase::Duration::QUICK);

  // RFC 9002 §5.3 — kInitialRtt
  AddTestCase (new QuicInitialRttTestCase,               TestCase::Duration::QUICK);

  // RFC 9002 §7.6.3 — Persistent congestion
  AddTestCase (new QuicPersistentCongestionThresholdTestCase,    TestCase::Duration::QUICK);
  AddTestCase (new QuicPersistentCongestionDetectionTestCase,    TestCase::Duration::QUICK);
  AddTestCase (new QuicNoPersistentCongestionTestCase,           TestCase::Duration::QUICK);
  AddTestCase (new QuicPersistentCongestionNoRttTestCase,        TestCase::Duration::QUICK);

  // RFC 9000 §17.3.1 — Spin Bit
  AddTestCase (new QuicSpinBitTestCase,                          TestCase::Duration::QUICK);

  // RFC 9000 §18.2 — Transport Parameters
  AddTestCase (new QuicActiveConnIdLimitTestCase,                TestCase::Duration::QUICK);
  AddTestCase (new QuicStatelessResetTokenTestCase,              TestCase::Duration::QUICK);

  // RFC 9000 §20 — FRAME_ENCODING_ERROR
  AddTestCase (new QuicFrameEncodingErrorTestCase,               TestCase::Duration::QUICK);
}

static QuicTestSuite sQuicTestSuite;
