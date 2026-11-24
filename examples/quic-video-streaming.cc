/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/*
 * quic-video-streaming.cc
 *
 * Mídia ao vivo de baixa latência sobre QUIC (módulo contrib/quic) vs TCP no NS-3.
 *
 * Topologia: servidor --(gargalo: banda/atraso/perda)-- cliente.
 * O servidor envia, em UMA única conexão, três fluxos de mídia:
 *   stream 1: vídeo   (quadros a 30 fps, ~bitrate configurável)
 *   stream 2: áudio   (pacotes a cada 20 ms)
 *   stream 3: metadados/controle (a cada 100 ms)
 * Cada mensagem tem um cabeçalho de aplicação (stream, seq, tamanho, instante
 * de envio) que permite ao cliente medir o atraso de entrega por fluxo.
 * Com TCP, as mesmas mensagens são intercaladas em um único byte-stream.
 *
 * Contabilidade das mensagens (igual para QUIC e TCP):
 *   - a mídia é gerada em instantes fixos, de --streamTime segundos, e o carimbo de cada mensagem é
 * o instante em que ela foi GERADA; uma mensagem que espera (conexão ainda abrindo, buffer de envio
 * cheio) entra no atraso;
 *   - nenhuma mensagem é descartada pela aplicação: as que não cabem no buffer ficam numa fila e
 * são reenviadas;
 *   - a mensagem não entregue até o fim da simulação conta com atraso = (fim - geração), um limite
 * inferior do atraso real, e entra na média, nos percentis, no máximo e em late150_pct;
 * "undelivered" as conta.
 *   - os quadros de vídeo usam um gerador aleatório de stream fixo: com a mesma repetição (--run),
 * QUIC e TCP recebem a mesma sequência de tamanhos.
 *
 * TCP: --tcpProfile=ns3 usa os padrões do ns-3 (RTO mínimo de 1 s, timeout do SYN de 3 s, atraso de
 * ACK de 200 ms, buffers de 128 KB); --tcpProfile=linux-timers usa os temporizadores e buffers do
 * Linux (RTO mínimo de 200 ms, timeout do SYN de 1 s, atraso de ACK de 40 ms, buffers de 4 MiB),
 * mas o TCP continua sendo o do ns-3, sem Tail Loss Probe nem RACK. O atraso de ACK precisa ser bem
 * menor que o RTO mínimo: com RTO mínimo de 200 ms e o atraso de ACK padrão do ns-3 (200 ms) o TCP
 * entra em ciclo de RTOs espúrios, pois o receptor segura o ACK de um único segmento até o RTO
 * disparar. --tcpMinRto=<ms> troca o RTO mínimo do perfil. --tcpPacing=1 liga o pacing do TCP (o
 * CUBIC do QUIC faz pacing). A coluna rto_episodes conta as entradas do TCP no estado CA_LOSS:
 * vários RTOs seguidos, com o recuo exponencial do temporizador, contam uma vez; no QUIC vale -1. A
 * coluna pacing_below_pct é, no TCP com pacing, a parte da janela de mídia (em %) em que a taxa de
 * pacing ficou abaixo da carga oferecida; vale -1 sem pacing e no QUIC. Com RTO mínimo de 60 ms e
 * atraso de ACK de 40 ms o TCP entra em ciclo de RTOs espúrios: --tcpMinRto não deve ficar perto do
 * atraso de ACK mais o RTT.
 *
 * Uso:
 *   ./ns3 run "quic-video-streaming --transport=quic --loss=0.02 --run=1"
 * Saída: uma linha CSV por fluxo (use --header=1 para imprimir o cabeçalho).
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/quic-helper.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-socket-factory.h"
#include "ns3/quic-socket-tx-edf-scheduler.h"
#include "ns3/quic-socket-tx-pfifo-scheduler.h"
#include "ns3/quic-socket-tx-roundrobin-scheduler.h"
#include "ns3/quic-socket-tx-streamfifo-scheduler.h"
#include "ns3/quic-stream-id-tag.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("QuicVideoStreaming");

namespace
{
constexpr uint32_t kMagic = 0x51564944; // "QVID"
constexpr uint32_t kHdrSize = 24;

struct MsgHeader
{
    uint32_t magic;
    uint32_t stream;
    uint32_t seq;
    uint32_t size; // bytes de carga útil após o cabeçalho
    uint64_t sentNs;
};

struct StreamStats
{
    std::vector<double> delaysMs; // mensagens entregues
    std::vector<int64_t> sentNs;  // instante de geração de cada mensagem, por número de sequência
    std::vector<char> got;        // a mensagem de número de sequência i foi entregue
    uint64_t bytes = 0;
    uint32_t sent = 0;
};

std::map<uint32_t, StreamStats> g_stats;
std::map<uint32_t, std::vector<uint8_t>> g_rxBufs; // reassembly por stream (QUIC) ou 0 (TCP)
bool g_corrupt = false;

uint32_t g_drops = 0;
Ptr<Socket> g_serverConn;
Ptr<Socket> g_serverListen;
Ptr<Socket> g_client;
std::string g_transport = "quic";
Time g_streamStart;
Time g_streamEnd;

// Parâmetros de mídia
uint32_t g_videoBitrate = 1000000; // bps
uint32_t g_fps = 30;
uint32_t g_audioBytes = 160;
Time g_audioInterval = MilliSeconds(20);
uint32_t g_metaBytes = 100;
Time g_metaInterval = MilliSeconds(100);
std::map<uint32_t, uint32_t> g_seq;
double g_offeredBps =
    0; // carga oferecida pela aplicação, em bit/s (com os cabeçalhos das mensagens)
double g_paceBelowS = 0; // TCP com pacing: tempo, dentro da janela de mídia, em que a taxa de
                         // pacing ficou abaixo da carga
double g_paceLastT = 0;
double g_paceLastBps = -1; // taxa de pacing em vigor desde g_paceLastT (-1: ainda desconhecida)
uint32_t g_rtos = 0;       // TCP: episódios de RTO (entradas no estado CA_LOSS)
std::map<uint32_t, std::deque<MsgHeader>> g_backlog; // mensagens geradas que ainda não couberam no
                                                     // socket (QUIC: por stream; TCP: chave 0)
Ptr<UniformRandomVariable> g_videoRv;                // tamanho dos quadros de vídeo, stream fixo
Time g_simEnd;
bool g_prioritizeAudio = false;

// Cenários de rede e de conexão
double g_burst = 0;             // comprimento médio da rajada de perdas (0 = perda uniforme)
double g_jitterMs = 0;          // atraso extra uniforme em [0, jitter] ms, preservando a ordem
double g_pathChangeAt = 0;      // instante da mudança de caminho (s); 0 = sem mudança
double g_pathDelayMs = 40;      // atraso de propagação (um sentido) depois da mudança
std::string g_pathBw = "5Mbps"; // banda depois da mudança
double g_reconnect = 1.0;       // TCP: tempo sem dados até o aplicativo reconectar (s)
bool g_tls = false;             // TCP: handshake TLS 1.3 completo depois do TCP
uint32_t g_tlsClientHello = 300;
uint32_t g_tlsServerFlight = 3000;
uint32_t g_tlsClientFinished = 80;
Time g_connectAt = Seconds(0.5);
Time g_helloAt = Seconds(0);    // quando a primeira mensagem (hello) chegou ao cliente
std::vector<double> g_arrivals; // instantes de chegada de mensagens de mídia (s)
Ptr<Node> g_clientNode;
Ipv4Address g_serverAddr;
Ipv4Address g_newLocal;
uint64_t g_cliTlsSkip = 0; // bytes de TLS que o cliente TCP ainda deve descartar
uint64_t g_srvTlsRx = 0;
bool g_srvReady = false;
void ClientRead(Ptr<Socket> s);
void ServerAccept(Ptr<Socket> s, const Address&);

/**
 * Modelo de recepção: perda uniforme ou em rajadas e jitter (atraso extra por pacote, sem
 * reordenar). Os pacotes com atraso são recolhidos e reinseridos no dispositivo depois.
 */
class ImpairModel : public ErrorModel
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("ns3::QvsImpairModel").SetParent<ErrorModel>().AddConstructor<ImpairModel>();
        return tid;
    }

    void Setup(Ptr<PointToPointNetDevice> dev, Ptr<ErrorModel> loss, double jitterMs)
    {
        m_dev = dev;
        m_loss = loss;
        m_jitter = MilliSeconds(1) * jitterMs;
        m_rng = CreateObject<UniformRandomVariable>();
        m_rng->SetStream(101);
    }

  private:
    bool DoCorrupt(Ptr<Packet> p) override
    {
        if (m_reinject)
        {
            return false;
        }
        if (m_loss && m_loss->IsCorrupt(p))
        {
            ++g_drops;
            return true;
        }
        if (m_jitter.IsStrictlyPositive())
        {
            Time extra = Time::FromDouble(m_rng->GetValue(0, m_jitter.GetSeconds()), Time::S);
            Time release = std::max(m_lastRelease, Simulator::Now() + extra);
            m_lastRelease = release;
            Simulator::Schedule(release - Simulator::Now(),
                                &ImpairModel::Reinject,
                                this,
                                p->Copy());
            return true;
        }
        return false;
    }

    void Reinject(Ptr<Packet> p)
    {
        m_reinject = true;
        m_dev->Receive(p);
        m_reinject = false;
    }

    void DoReset() override
    {
    }

    Ptr<PointToPointNetDevice> m_dev;
    Ptr<ErrorModel> m_loss;
    Ptr<UniformRandomVariable> m_rng;
    Time m_jitter;
    Time m_lastRelease;
    bool m_reinject = false;
};

void
Flush(uint32_t key)
{
    std::deque<MsgHeader>& q = g_backlog[key];
    while (g_serverConn && !q.empty())
    {
        const MsgHeader& h = q.front();
        std::vector<uint8_t> buf(kHdrSize + h.size, 0);
        std::memcpy(buf.data(), &h, kHdrSize);
        Ptr<Packet> p = Create<Packet>(buf.data(), buf.size());
        int r;
        if (g_transport == "quic")
        {
            r = g_serverConn->Send(
                p,
                4 * (h.stream - 1) +
                    1); // RFC 9000 id of the n-th server-initiated bidirectional stream
        }
        else
        {
            r = g_serverConn->Send(p);
        }
        if (r < 0)
        {
            break; // transmit buffer full: the message waits, keeping the instant it was generated
        }
        q.pop_front();
    }
}

void
FlushAll()
{
    for (auto& kv : g_backlog)
    {
        Flush(kv.first);
    }
}

void
AccountPacing(double now)
{
    double from = std::max(g_paceLastT, g_streamStart.GetSeconds());
    double to = std::min(now, g_streamEnd.GetSeconds());
    if (g_paceLastBps >= 0 && g_paceLastBps < g_offeredBps && to > from)
    {
        g_paceBelowS += to - from;
    }
    g_paceLastT = now;
}

void
OnPacingRate(DataRate, DataRate newRate)
{
    AccountPacing(Simulator::Now().GetSeconds());
    g_paceLastBps = (double)newRate.GetBitRate();
}

void
OnTcpCongState(TcpSocketState::TcpCongState_t oldState, TcpSocketState::TcpCongState_t newState)
{
    if (newState == TcpSocketState::CA_LOSS && oldState != TcpSocketState::CA_LOSS)
    {
        ++g_rtos;
    }
}

void
OnSendSpace(Ptr<Socket>, uint32_t)
{
    FlushAll();
}

// A message is generated at a fixed instant whatever the state of the connection; it is stamped
// with that instant
void
SendMessage(uint32_t stream, uint32_t payload)
{
    MsgHeader h{kMagic,
                stream,
                g_seq[stream]++,
                payload,
                (uint64_t)Simulator::Now().GetNanoSeconds()};
    StreamStats& st = g_stats[stream];
    st.sent++;
    st.sentNs.push_back((int64_t)h.sentNs);
    st.got.push_back(0);
    uint32_t key = (g_transport == "quic") ? stream : 0;
    g_backlog[key].push_back(h);
    Flush(key);
}

void
VideoTick()
{
    if (Simulator::Now() >= g_streamEnd)
    {
        return;
    }
    // quadros de tamanho variável (±30%) com média = bitrate/fps
    uint32_t mean = g_videoBitrate / 8 / g_fps;
    uint32_t sz = (uint32_t)(mean * g_videoRv->GetValue(0.7, 1.3));
    SendMessage(1, sz);
    Simulator::Schedule(Seconds(1.0 / g_fps), &VideoTick);
}

void
AudioTick()
{
    if (Simulator::Now() >= g_streamEnd)
    {
        return;
    }
    SendMessage(2, g_audioBytes);
    Simulator::Schedule(g_audioInterval, &AudioTick);
}

void
MetaTick()
{
    if (Simulator::Now() >= g_streamEnd)
    {
        return;
    }
    SendMessage(3, g_metaBytes);
    Simulator::Schedule(g_metaInterval, &MetaTick);
}

void
BeginTicks()
{
    VideoTick();
    AudioTick();
    MetaTick();
}

// Mensagem de abertura (stream 0): mede o tempo até o primeiro byte da aplicação
void
SendHello(Ptr<Socket> s)
{
    MsgHeader h{kMagic, 0, 0, 0, (uint64_t)Simulator::Now().GetNanoSeconds()};
    std::vector<uint8_t> buf(kHdrSize, 0);
    std::memcpy(buf.data(), &h, kHdrSize);
    Ptr<Packet> p = Create<Packet>(buf.data(), buf.size());
    if (g_transport == "quic")
    {
        s->Send(p, 1);
    }
    else
    {
        s->Send(p);
    }
}

void
ServerReady(Ptr<Socket> s)
{
    g_serverConn = s;
    if (g_transport == "quic" && g_prioritizeAudio)
    {
        // msquic QUIC_PARAM_STREAM_PRIORITY: audio and metadata ahead of video (default 0x7FFF)
        Ptr<QuicSocketBase> qs = DynamicCast<QuicSocketBase>(s);
        qs->SetStreamPriority(5, 0xFFFF);
        qs->SetStreamPriority(9, 0xFFFF);
    }
    s->SetSendCallback(MakeCallback(&OnSendSpace));
    if (g_transport == "tcp")
    {
        s->TraceConnectWithoutContext("CongState", MakeCallback(&OnTcpCongState));
        DynamicCast<TcpSocketBase>(s)->TraceConnectWithoutContext("PacingRate",
                                                                  MakeCallback(&OnPacingRate));
    }
    SendHello(s);
    FlushAll(); // what was generated while the connection was opening goes out now
}

// Servidor TCP: acompanha o handshake TLS 1.3 (ClientHello, voo do servidor, Finished do cliente)
void
ServerTlsRead(Ptr<Socket> s)
{
    Ptr<Packet> p;
    while ((p = s->Recv()) && p->GetSize() > 0)
    {
        uint64_t before = g_srvTlsRx;
        g_srvTlsRx += p->GetSize();
        if (before < g_tlsClientHello && g_srvTlsRx >= g_tlsClientHello)
        {
            // o servidor responde com o seu voo (ServerHello .. Finished)
            s->Send(Create<Packet>(g_tlsServerFlight));
        }
        if (!g_srvReady && g_srvTlsRx >= g_tlsClientHello + g_tlsClientFinished)
        {
            g_srvReady = true;
            ServerReady(s);
        }
    }
}

void
ServerAccept(Ptr<Socket> s, const Address&)
{
    if (g_transport == "tcp" && g_tls)
    {
        g_srvTlsRx = 0;
        g_srvReady = false;
        s->SetRecvCallback(MakeCallback(&ServerTlsRead));
        return;
    }
    ServerReady(s);
}

void
ParseStream(std::vector<uint8_t>& buf)
{
    size_t off = 0;
    while (buf.size() - off >= kHdrSize)
    {
        MsgHeader h;
        std::memcpy(&h, buf.data() + off, kHdrSize);
        if (h.magic != kMagic)
        {
            g_corrupt = true;
            buf.clear();
            return;
        }
        if (buf.size() - off < kHdrSize + h.size)
        {
            break;
        }
        if (h.stream == 0)
        {
            if (g_helloAt.IsZero())
            {
                g_helloAt = Simulator::Now();
            }
            off += kHdrSize + h.size;
            continue;
        }
        g_arrivals.push_back(Simulator::Now().GetSeconds());
        double d = (Simulator::Now().GetNanoSeconds() - (int64_t)h.sentNs) / 1e6;
        if (d > 150 && std::getenv("DEBUGLAT"))
        {
            std::cerr << "LAT stream=" << h.stream << " seq=" << h.seq << " sent=" << h.sentNs / 1e9
                      << " delay=" << d << "\n";
        }
        StreamStats& st = g_stats[h.stream];
        st.delaysMs.push_back(d);
        st.bytes += kHdrSize + h.size;
        if (h.seq < st.got.size())
        {
            st.got[h.seq] = 1;
        }
        off += kHdrSize + h.size;
    }
    buf.erase(buf.begin(), buf.begin() + off);
}

void
ClientRead(Ptr<Socket> s)
{
    Ptr<Packet> p;
    while ((p = s->Recv()) && p->GetSize() > 0)
    {
        std::vector<uint8_t> raw(p->GetSize());
        p->CopyData(raw.data(), raw.size());
        if (g_transport == "tcp" && g_cliTlsSkip > 0)
        {
            // the first bytes of a TLS connection are the server flight, not media
            uint64_t skip = std::min<uint64_t>(g_cliTlsSkip, raw.size());
            g_cliTlsSkip -= skip;
            raw.erase(raw.begin(), raw.begin() + skip);
            if (g_cliTlsSkip == 0)
            {
                s->Send(Create<Packet>(g_tlsClientFinished));
            }
            if (raw.empty())
            {
                continue;
            }
        }
        if (g_transport == "quic")
        {
            // QuicStreamIdTag identifica o stream de cada faixa de bytes
            std::vector<uint32_t> touched;
            for (ByteTagIterator it = p->GetByteTagIterator(); it.HasNext();)
            {
                ByteTagIterator::Item item = it.Next();
                if (item.GetTypeId() != QuicStreamIdTag::GetTypeId())
                {
                    continue;
                }
                QuicStreamIdTag tag;
                item.GetTag(tag);
                uint32_t sid = (uint32_t)tag.GetStreamId();
                auto& b = g_rxBufs[sid];
                b.insert(b.end(), raw.begin() + item.GetStart(), raw.begin() + item.GetEnd());
                touched.push_back(sid);
            }
            for (uint32_t sid : touched)
            {
                ParseStream(g_rxBufs[sid]);
            }
        }
        else
        {
            auto& b = g_rxBufs[0];
            b.insert(b.end(), raw.begin(), raw.end());
            ParseStream(b);
        }
    }
}

double
Pct(std::vector<double> v, double q)
{
    if (v.empty())
    {
        return 0;
    }
    std::sort(v.begin(), v.end());
    return v[std::min(v.size() - 1, (size_t)(q * v.size()))];
}
} // namespace

void
TcpConnected(Ptr<Socket> s)
{
    if (g_tls)
    {
        g_cliTlsSkip = g_tlsServerFlight;
        s->Send(Create<Packet>(g_tlsClientHello));
    }
}

void
StartTcpClient(Ipv4Address local)
{
    Ptr<Socket> c =
        Socket::CreateSocket(g_clientNode, TypeId::LookupByName("ns3::TcpSocketFactory"));
    if (local != Ipv4Address::GetAny())
    {
        c->Bind(InetSocketAddress(local, 0));
    }
    c->SetRecvCallback(MakeCallback(&ClientRead));
    c->SetConnectCallback(MakeCallback(&TcpConnected), MakeNullCallback<void, Ptr<Socket>>());
    g_client = c;
    g_rxBufs.clear();
    c->Connect(InetSocketAddress(g_serverAddr, 443));
}

// Mudança de caminho: nova banda e atraso, o endereço antigo do cliente some e o novo passa a valer
void
PathChange(NetDeviceContainer devs)
{
    for (uint32_t i = 0; i < 2; ++i)
    {
        devs.Get(i)->SetAttribute("DataRate", DataRateValue(DataRate(g_pathBw)));
    }
    devs.Get(0)->GetChannel()->SetAttribute("Delay", TimeValue(MilliSeconds(1) * g_pathDelayMs));
    if (g_transport == "quic")
    {
        DynamicCast<QuicSocketBase>(g_client)->Migrate(InetSocketAddress(g_newLocal, 0));
    }
    Ptr<Ipv4> ipv4 = g_clientNode->GetObject<Ipv4>();
    ipv4->RemoveAddress(1, 0); // the old address goes away with the old interface
    // removing the first address also removes the connected route of the subnet: put the new one
    // back
    ipv4->RemoveAddress(1, 0);
    ipv4->AddAddress(1, Ipv4InterfaceAddress(g_newLocal, Ipv4Mask("255.255.255.0")));
    if (g_transport == "tcp")
    {
        // the application notices the stall after g_reconnect seconds and opens a new connection
        Simulator::Schedule(Seconds(g_reconnect), []() { StartTcpClient(g_newLocal); });
    }
}

int
main(int argc, char* argv[])
{
    std::string transport = "quic";
    std::string bw = "10Mbps";
    std::string delay = "20ms";
    double loss = 0.0;
    double streamTime = 30.0;
    uint32_t run = 1;
    uint32_t header = 0;
    std::string sched = "sfifo";
    std::string cc = "cubic";
    std::string tcpProfile = "ns3";
    bool tcpPacing = false;
    uint32_t tcpMinRtoMs = 0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("transport", "quic | tcp", transport);
    cmd.AddValue("bw", "Largura de banda do gargalo", bw);
    cmd.AddValue("delay", "Atraso de propagação (um sentido)", delay);
    cmd.AddValue("loss", "Taxa de perda de pacotes (0..1) no enlace", loss);
    cmd.AddValue("streamTime", "Duração da transmissão (s)", streamTime);
    cmd.AddValue("videoBitrate", "Bitrate de vídeo (bps)", g_videoBitrate);
    cmd.AddValue("prioritizeAudio",
                 "QUIC: dar prioridade de stream maior ao áudio e metadados",
                 g_prioritizeAudio);
    cmd.AddValue("run", "Índice da repetição (RngRun)", run);
    cmd.AddValue("sched",
                 "Escalonador QUIC: sfifo (FIFO por stream, padrão msquic) | rr (round-robin do "
                 "msquic) | fifo (por quadro) | pfifo | edf",
                 sched);
    cmd.AddValue("cc", "Controle de congestionamento QUIC: cubic | newreno | bbr", cc);
    cmd.AddValue("header", "Imprimir cabeçalho CSV", header);
    cmd.AddValue("burst", "Comprimento médio da rajada de perdas (0 = perda uniforme)", g_burst);
    cmd.AddValue("jitter", "Jitter: atraso extra uniforme em [0, jitter] ms", g_jitterMs);
    cmd.AddValue("pathChange", "Instante (s) da mudança de caminho; 0 = nenhuma", g_pathChangeAt);
    cmd.AddValue("pathDelay", "Atraso de propagação (ms) depois da mudança", g_pathDelayMs);
    cmd.AddValue("pathBw", "Banda depois da mudança", g_pathBw);
    cmd.AddValue("reconnect", "TCP: tempo (s) sem dados até o aplicativo reconectar", g_reconnect);
    cmd.AddValue("tls", "TCP: incluir o handshake TLS 1.3 completo", g_tls);
    cmd.AddValue("tcpProfile",
                 "TCP: ns3 (padrões do ns-3) | linux-timers (RTO mínimo 200 ms, timeout do SYN 1 "
                 "s, atraso de ACK 40 ms, buffers de 4 MiB)",
                 tcpProfile);
    cmd.AddValue("tcpMinRto", "TCP: RTO mínimo em ms (0 = o do perfil)", tcpMinRtoMs);
    cmd.AddValue("tcpPacing", "TCP: ligar o pacing", tcpPacing);
    cmd.Parse(argc, argv);
    g_transport = transport;
    if (std::getenv("PKTMETA"))
    {
        Packet::EnablePrinting();
    }

    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(run);
    // fixed streams: the same video frames in every variant of a repetition, whatever else draws
    // numbers
    g_videoRv = CreateObject<UniformRandomVariable>();
    g_videoRv->SetStream(100);

    if (transport == "quic")
    {
        const char* ccType = cc == "bbr"       ? "ns3::QuicBbr"
                             : cc == "newreno" ? "ns3::QuicCongestionControl"
                                               : "ns3::QuicCubic";
        Config::SetDefault("ns3::QuicL4Protocol::SocketType",
                           TypeIdValue(TypeId::LookupByName(ccType)));
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(8));
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdUni", UintegerValue(8));
    }
    if (transport == "tcp")
    {
        Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpCubic"));
        Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
        if (tcpProfile == "linux-timers")
        {
            Config::SetDefault("ns3::TcpSocketBase::MinRto", TimeValue(MilliSeconds(200)));
            Config::SetDefault("ns3::TcpSocket::ConnTimeout", TimeValue(Seconds(1)));
            Config::SetDefault("ns3::TcpSocket::DelAckTimeout", TimeValue(MilliSeconds(40)));
            Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(4 * 1024 * 1024));
            Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(4 * 1024 * 1024));
        }
        if (tcpMinRtoMs > 0)
        {
            Config::SetDefault("ns3::TcpSocketBase::MinRto", TimeValue(MilliSeconds(tcpMinRtoMs)));
        }
        Config::SetDefault("ns3::TcpSocketState::EnablePacing", BooleanValue(tcpPacing));
    }
    else
    {
        if (sched == "fifo")
        {
            Config::SetDefault("ns3::QuicSocketBase::SchedulingPolicy",
                               TypeIdValue(QuicSocketTxScheduler::GetTypeId()));
        }
        else if (sched == "pfifo")
        {
            Config::SetDefault("ns3::QuicSocketBase::SchedulingPolicy",
                               TypeIdValue(QuicSocketTxPFifoScheduler::GetTypeId()));
        }
        else if (sched == "rr")
        {
            Config::SetDefault("ns3::QuicSocketBase::SchedulingPolicy",
                               TypeIdValue(QuicSocketTxRoundRobinScheduler::GetTypeId()));
        }
        else if (sched == "sfifo")
        {
            Config::SetDefault("ns3::QuicSocketBase::SchedulingPolicy",
                               TypeIdValue(QuicSocketTxStreamFifoScheduler::GetTypeId()));
        }
        else if (sched == "edf")
        {
            Config::SetDefault("ns3::QuicSocketBase::SchedulingPolicy",
                               TypeIdValue(QuicSocketTxEdfScheduler::GetTypeId()));
        }
    }

    NodeContainer nodes;
    nodes.Create(2); // 0 = servidor, 1 = cliente
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(bw));
    p2p.SetChannelAttribute("Delay", StringValue(delay));
    NetDeviceContainer dev = p2p.Install(nodes);

    if (loss > 0 || g_jitterMs > 0)
    {
        Ptr<ErrorModel> inner;
        if (loss > 0 && g_burst > 1)
        {
            // rajadas: início com probabilidade loss/burst, comprimento uniforme em [1, 2*burst-1]
            Ptr<BurstErrorModel> bm = CreateObject<BurstErrorModel>();
            bm->SetAttribute("ErrorRate", DoubleValue(loss / g_burst));
            Ptr<UniformRandomVariable> len = CreateObject<UniformRandomVariable>();
            len->SetAttribute("Min", DoubleValue(1));
            len->SetAttribute("Max", DoubleValue(2 * g_burst - 1));
            len->SetStream(104);
            bm->AssignStreams(103);
            bm->SetRandomBurstSize(len);
            inner = bm;
        }
        else if (loss > 0)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetAttribute("ErrorRate", DoubleValue(loss));
            em->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
            em->AssignStreams(102);
            inner = em;
        }
        Ptr<ImpairModel> model = CreateObject<ImpairModel>();
        model->Setup(DynamicCast<PointToPointNetDevice>(dev.Get(1)), inner, g_jitterMs);
        dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(model));
    }

    InternetStackHelper internet;
    internet.Install(nodes);
    QuicHelper quic;
    if (transport == "quic")
    {
        quic.InstallQuic(nodes);
    }
    Ipv4AddressHelper ip;
    ip.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifs = ip.Assign(dev);

    const uint16_t port = 443;
    TypeId tid = (transport == "quic") ? QuicSocketFactory::GetTypeId()
                                       : TypeId::LookupByName("ns3::TcpSocketFactory");

    g_serverListen = Socket::CreateSocket(nodes.Get(0), tid);
    g_serverListen->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
    g_serverListen->Listen();
    g_serverListen->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                      MakeCallback(&ServerAccept));

    g_clientNode = nodes.Get(1);
    g_serverAddr = ifs.GetAddress(0);
    g_newLocal = Ipv4Address("10.1.1.77");
    if (g_pathChangeAt > 0)
    {
        // the client has a second address for the path it will move to
        g_clientNode->GetObject<Ipv4>()->AddAddress(
            1,
            Ipv4InterfaceAddress(g_newLocal, Ipv4Mask("255.255.255.0")));
    }
    g_offeredBps = ((g_videoBitrate / 8.0 / g_fps + kHdrSize) * g_fps +
                    (g_audioBytes + kHdrSize) / g_audioInterval.GetSeconds() +
                    (g_metaBytes + kHdrSize) / g_metaInterval.GetSeconds()) *
                   8.0;
    g_streamStart = Seconds(1.0);
    g_streamEnd = g_streamStart + Seconds(streamTime);
    if (transport == "quic")
    {
        g_client = Socket::CreateSocket(nodes.Get(1), tid);
        g_client->SetRecvCallback(MakeCallback(&ClientRead));
        Simulator::Schedule(g_connectAt, [&]() {
            g_client->Connect(InetSocketAddress(ifs.GetAddress(0), port));
        });
    }
    else
    {
        Simulator::Schedule(g_connectAt, []() { StartTcpClient(Ipv4Address::GetAny()); });
    }
    if (g_pathChangeAt > 0)
    {
        Simulator::Schedule(Seconds(g_pathChangeAt), &PathChange, dev);
    }

    Simulator::Schedule(g_streamStart, &BeginTicks);
    g_simEnd = g_streamEnd + Seconds(10);
    Simulator::Stop(g_simEnd);
    Simulator::Run();
    Simulator::Destroy();

    if (header)
    {
        std::cout << "transport,sched,cc,loss,run,stream,sent,delivered,mean_ms,p95_ms,p99_ms,"
                     "max_ms,goodput_mbps,corrupt,late150_pct,burst,jitter_ms,path_change,ttfb_ms,"
                     "max_gap_ms,undelivered,rto_episodes,pacing_below_pct\n";
    }
    AccountPacing(g_streamEnd.GetSeconds());
    std::cerr << "drops=" << g_drops << "\n";
    double ttfb = g_helloAt.IsZero() ? -1 : (g_helloAt - g_connectAt).GetMilliSeconds();
    std::sort(g_arrivals.begin(), g_arrivals.end());
    double maxGap = 0;
    for (size_t i = 1; i < g_arrivals.size(); ++i)
    {
        if (g_arrivals[i - 1] >= g_streamStart.GetSeconds())
        {
            maxGap = std::max(maxGap, (g_arrivals[i] - g_arrivals[i - 1]) * 1000.0);
        }
    }
    const char* names[] = {"", "video", "audio", "meta"};
    for (uint32_t s = 1; s <= 3; ++s)
    {
        StreamStats& st = g_stats[s];
        // every message that was generated counts; one that never arrived has a delay of at least
        // (end - generation)
        std::vector<double> all = st.delaysMs;
        uint32_t undelivered = 0;
        for (size_t i = 0; i < st.got.size(); ++i)
        {
            if (!st.got[i])
            {
                all.push_back((g_simEnd.GetNanoSeconds() - st.sentNs[i]) / 1e6);
                ++undelivered;
            }
        }
        double mean = 0;
        for (double d : all)
        {
            mean += d;
        }
        mean = all.empty() ? 0 : mean / all.size();
        uint32_t late = 0;
        for (double d : all)
        {
            late += (d > 150.0) ? 1 : 0;
        }
        double latePct = all.empty() ? 0 : 100.0 * late / all.size();
        std::cout << transport << ","
                  << (transport == "quic" ? sched + (g_prioritizeAudio ? "+prio" : "")
                                          : std::string("-"))
                  << "," << (transport == "quic" ? cc : "cubic") << "," << loss << "," << run << ","
                  << names[s] << "," << st.sent << "," << st.delaysMs.size() << "," << mean << ","
                  << Pct(all, 0.95) << "," << Pct(all, 0.99) << "," << Pct(all, 1.0) << ","
                  << st.bytes * 8.0 / streamTime / 1e6 << "," << (g_corrupt ? 1 : 0) << ","
                  << latePct << "," << g_burst << "," << g_jitterMs << "," << g_pathChangeAt << ","
                  << ttfb << "," << maxGap << "," << undelivered << ","
                  << (transport == "tcp" ? (int)g_rtos : -1) << ","
                  << (transport == "tcp" && tcpPacing ? 100.0 * g_paceBelowS / streamTime : -1.0)
                  << "\n";
    }
    return 0;
}
