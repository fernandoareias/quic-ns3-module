/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * quic-example.cc
 *
 * Topologia: dois nós conectados por um enlace ponto-a-ponto.
 * Node 0 (servidor): escuta na porta 443 com socket QUIC.
 * Node 1 (cliente):  conecta ao servidor e envia uma mensagem.
 *
 * O servidor ecoa cada pacote recebido de volta ao cliente.
 * Ao final, são gerados arquivos .pcap no diretório corrente.
 *
 * Execução:
 *   ./ns3 run quic-example
 *   ./ns3 run "quic-example --simTime=5 --payload=512"
s */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/inet-socket-address.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/quic-helper.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-socket-factory.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("QuicExample");

static Ptr<Socket> g_clientSocket;
static Time g_sendTime;
static uint32_t g_payloadBytes = 64;
static uint16_t g_port = 443;

static void
ServerHandleRead(Ptr<Socket> socket)
{
    Ptr<Packet> pkt;
    Address from;
    while ((pkt = socket->RecvFrom(from)))
    {
        InetSocketAddress addr = InetSocketAddress::ConvertFrom(from);
        NS_LOG_UNCOND("[" << Simulator::Now().GetSeconds() << "s] Server: received "
                          << pkt->GetSize() << " bytes from " << addr.GetIpv4() << " — echoing");
        socket->SendTo(pkt, 0, from);
    }
}

static void
ServerHandleAccept(Ptr<Socket> socket, const Address& from)
{
    InetSocketAddress addr = InetSocketAddress::ConvertFrom(from);
    NS_LOG_UNCOND("[" << Simulator::Now().GetSeconds() << "s] Server: accepted connection from "
                      << addr.GetIpv4());
    socket->SetRecvCallback(MakeCallback(&ServerHandleRead));
}

static void
StartServer(Ptr<Node> node, Ipv4Address localAddr)
{
    Ptr<Socket> serverSocket = Socket::CreateSocket(node, QuicSocketFactory::GetTypeId());

    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), g_port);
    if (serverSocket->Bind(local) < 0)
    {
        NS_FATAL_ERROR("Server: Bind failed");
    }

    serverSocket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&ServerHandleAccept));
    serverSocket->Listen();

    NS_LOG_UNCOND("[" << Simulator::Now().GetSeconds() << "s] Server: listening on " << localAddr
                      << ":" << g_port);
}

static void
ClientHandleRead(Ptr<Socket> socket)
{
    Ptr<Packet> pkt;
    Address from;
    while ((pkt = socket->RecvFrom(from)))
    {
        Time rtt = Simulator::Now() - g_sendTime;
        NS_LOG_UNCOND("[" << Simulator::Now().GetSeconds() << "s] Client: received echo "
                          << pkt->GetSize() << " bytes  RTT ~ " << rtt.GetMilliSeconds() << "ms");
    }
}

static void
ClientHandleConnect(Ptr<Socket> socket)
{
    NS_LOG_UNCOND("[" << Simulator::Now().GetSeconds() << "s] Client: connected, sending "
                      << g_payloadBytes << " bytes");
    g_sendTime = Simulator::Now();
    Ptr<Packet> pkt = Create<Packet>(g_payloadBytes);
    socket->Send(pkt);
}

static void
ClientHandleConnectFailed(Ptr<Socket> socket)
{
    NS_FATAL_ERROR("Client: connection failed");
}

static void
StartClient(Ptr<Node> node, Ipv4Address serverAddr)
{
    g_clientSocket = Socket::CreateSocket(node, QuicSocketFactory::GetTypeId());
    g_clientSocket->SetConnectCallback(MakeCallback(&ClientHandleConnect),
                                       MakeCallback(&ClientHandleConnectFailed));
    g_clientSocket->SetRecvCallback(MakeCallback(&ClientHandleRead));

    InetSocketAddress remote(serverAddr, g_port);
    g_clientSocket->Connect(remote);
}

int
main(int argc, char* argv[])
{
    double simTime = 5.0;
    uint32_t payloadB = g_payloadBytes;
    bool verbose = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Simulation duration (s)", simTime);
    cmd.AddValue("payload", "Client payload size in bytes", payloadB);
    cmd.AddValue("verbose", "Enable QUIC debug logs", verbose);
    cmd.Parse(argc, argv);

    // Like msquic, no stream may be opened by the peer until the application allows some
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4));
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdUni", UintegerValue(4));

    g_payloadBytes = payloadB;

    if (verbose)
    {
        LogComponentEnable("QuicSocketBase", LOG_LEVEL_DEBUG);
        LogComponentEnable("QuicL4Protocol", LOG_LEVEL_DEBUG);
        LogComponentEnable("QuicExample", LOG_LEVEL_ALL);
    }

    NodeContainer nodes;
    nodes.Create(2);
    Ptr<Node> serverNode = nodes.Get(0);
    Ptr<Node> clientNode = nodes.Get(1);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("5ms"));

    NetDeviceContainer devices = p2p.Install(nodes);

    QuicHelper quic;
    quic.InstallQuic(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    Ipv4Address serverAddr = ifaces.GetAddress(0);
    (void)ifaces.GetAddress(1);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Simulator::Schedule(Seconds(0.0), &StartServer, serverNode, serverAddr);
    Simulator::Schedule(Seconds(0.1), &StartClient, clientNode, serverAddr);

    p2p.EnablePcapAll("quic-example");

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    std::cout << "\nSimulation done.\n"
              << "  pcap files: quic-example-0-0.pcap  quic-example-1-0.pcap\n"
              << "  Open with: wireshark quic-example-0-0.pcap\n";

    return 0;
}
