/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

/**
 * quic-loss-stress.cc
 *
 * Two nodes on a point-to-point link with random packet loss in both directions. Client and server each write
 * `--bytes` bytes on every one of `--nstreams` streams, and the program checks that every byte arrives. It prints
 * "OK" or "FAIL" with the byte counts and returns 0 or 1, so a shell loop over `--run` (the RNG run number), the loss
 * rate, the link and the congestion control is a stress test of the loss recovery and of the connection set-up.
 *
 * It found the lost-Handshake stall, the control frames that were never retransmitted, and the short header that was
 * read as an Initial packet (see the quic test suites for their regression tests).
 *
 * Usage:
 *   ./ns3 run "quic-loss-stress --loss=0.05 --run=7 --nstreams=3 --bytes=200000 --cc=ns3::QuicBbr"
 *
 * Note: --burst uses the ns-3 BurstErrorModel, which counts packets, not time. When only a few packets cross the link
 * (the sender backs off), one burst can last for many seconds, so failures with --burst at high rates are not
 * necessarily a protocol problem.
 */

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/quic-helper.h"
#include "ns3/quic-l4-protocol.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-socket-factory.h"

#include <iostream>
#include <vector>

using namespace ns3;

namespace
{

uint64_t g_bytesPerStream = 200000; //!< bytes each side writes on each stream
uint32_t g_streams = 1;             //!< streams each side writes on
uint64_t g_serverRx = 0;            //!< bytes the server received
uint64_t g_clientRx = 0;            //!< bytes the client received
std::vector<uint64_t> g_clientSent; //!< bytes the client wrote, per stream
std::vector<uint64_t> g_serverSent; //!< bytes the server wrote, per stream
bool g_transfer = true;             //!< false during the warm-up connection of --zrtt, which moves no data

void
Drain(uint64_t* counter, Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    while ((packet = socket->Recv()) && packet->GetSize() > 0)
    {
        *counter += packet->GetSize();
    }
}

void
Write(Ptr<Socket> socket, uint64_t* sent, uint64_t streamId)
{
    while (*sent < g_bytesPerStream)
    {
        uint32_t size = std::min<uint64_t>(1000, g_bytesPerStream - *sent);
        if (socket->GetTxAvailable() < size || socket->Send(Create<Packet>(size), streamId) < 0)
        {
            break;
        }
        *sent += size;
    }
    if (*sent < g_bytesPerStream)
    {
        Simulator::Schedule(MilliSeconds(5), &Write, socket, sent, streamId);
    }
}

void
Accepted(Ptr<Socket> socket, const Address&)
{
    socket->SetRecvCallback(MakeBoundCallback(&Drain, &g_serverRx));
    if (!g_transfer)
    {
        return;
    }
    g_serverSent.assign(g_streams, 0);
    for (uint32_t i = 0; i < g_streams; ++i)
    {
        Write(socket, &g_serverSent[i], 1 + 4 * i); // streams opened by the server: 1, 5, 9, ...
    }
}

void
Connected(Ptr<Socket> socket)
{
    if (!g_transfer)
    {
        return;
    }
    g_clientSent.assign(g_streams, 0);
    for (uint32_t i = 0; i < g_streams; ++i)
    {
        Write(socket, &g_clientSent[i], 4 * i); // streams opened by the client: 0, 4, 8, ...
    }
}

} // namespace

int
main(int argc, char* argv[])
{
    double loss = 0.05;
    uint32_t run = 1;
    std::string rate = "10Mbps";
    std::string delay = "10ms";
    double stop = 120;
    bool burst = false;
    uint32_t mtu = 1500;
    std::string cc = "ns3::QuicCubic";
    uint32_t maxStreamData = 0;
    uint32_t maxData = 0;
    bool zrtt = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("loss", "Packet loss probability (burst start probability with --burst)", loss);
    cmd.AddValue("run", "RNG run number", run);
    cmd.AddValue("bytes", "Bytes each side writes on each stream", g_bytesPerStream);
    cmd.AddValue("nstreams", "Streams each side writes on", g_streams);
    cmd.AddValue("rate", "Link data rate", rate);
    cmd.AddValue("delay", "Link delay", delay);
    cmd.AddValue("stop", "Simulation time limit in seconds", stop);
    cmd.AddValue("burst", "Use the burst error model instead of uniform loss", burst);
    cmd.AddValue("mtu", "Link MTU", mtu);
    cmd.AddValue("cc", "Congestion control TypeId", cc);
    cmd.AddValue("msd", "MaxStreamData, 0 keeps the default", maxStreamData);
    cmd.AddValue("md", "MaxData, 0 keeps the default", maxData);
    cmd.AddValue("zrtt", "Warm up with a first connection, then transfer over a 0-RTT connection", zrtt);
    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(7);
    RngSeedManager::SetRun(run);
    Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(4 * g_streams + 4));
    Config::SetDefault("ns3::QuicL4Protocol::SocketType", TypeIdValue(TypeId::LookupByName(cc)));
    if (maxStreamData)
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxStreamData", UintegerValue(maxStreamData));
    }
    if (maxData)
    {
        Config::SetDefault("ns3::QuicSocketBase::MaxData", UintegerValue(maxData));
    }

    NodeContainer nodes;
    nodes.Create(2);
    PointToPointHelper link;
    link.SetDeviceAttribute("DataRate", StringValue(rate));
    link.SetDeviceAttribute("Mtu", UintegerValue(mtu));
    link.SetChannelAttribute("Delay", StringValue(delay));
    NetDeviceContainer devices = link.Install(nodes);
    for (uint32_t i = 0; i < 2; ++i)
    {
        if (burst)
        {
            Ptr<BurstErrorModel> model = CreateObject<BurstErrorModel>();
            model->SetAttribute("ErrorRate", DoubleValue(loss));
            Ptr<UniformRandomVariable> length = CreateObject<UniformRandomVariable>();
            length->SetAttribute("Min", DoubleValue(1));
            length->SetAttribute("Max", DoubleValue(7));
            model->SetRandomBurstSize(length);
            devices.Get(i)->SetAttribute("ReceiveErrorModel", PointerValue(model));
        }
        else
        {
            Ptr<RateErrorModel> model = CreateObject<RateErrorModel>();
            model->SetAttribute("ErrorRate", DoubleValue(loss));
            model->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
            devices.Get(i)->SetAttribute("ReceiveErrorModel", PointerValue(model));
        }
    }

    InternetStackHelper internet;
    internet.Install(nodes);
    QuicHelper quic;
    quic.InstallQuic(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.9.5.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    TypeId factory = QuicSocketFactory::GetTypeId();
    Ptr<Socket> listener = Socket::CreateSocket(nodes.Get(0), factory);
    listener->Bind(InetSocketAddress(Ipv4Address::GetAny(), 4433));
    listener->Listen();
    listener->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                MakeCallback(&Accepted));
    auto startClient = [&nodes, &factory, &interfaces]() {
        Ptr<Socket> client = Socket::CreateSocket(nodes.Get(1), factory);
        client->SetRecvCallback(MakeBoundCallback(&Drain, &g_clientRx));
        client->SetConnectCallback(MakeCallback(&Connected), MakeNullCallback<void, Ptr<Socket>>());
        client->Connect(InetSocketAddress(interfaces.GetAddress(0), 4433));
        return client;
    };
    Ptr<Socket> client;
    if (zrtt)
    {
        // the server learns the client address in a first connection that moves no data, and the second one
        // starts with 0-RTT data
        g_transfer = false;
        Simulator::Schedule(Seconds(0.1), [&client, &startClient]() { client = startClient(); });
        Simulator::Schedule(Seconds(2.0), [&client]() { client->Close(); });
        Simulator::Schedule(Seconds(40.0), [&nodes, &client, &startClient]() {
            g_transfer = true;
            // the client sends 0-RTT data and the server accepts it: both stacks have to allow it
            nodes.Get(1)->GetObject<QuicL4Protocol>()->SetAttribute("0RTT-Handshake", BooleanValue(true));
            nodes.Get(0)->GetObject<QuicL4Protocol>()->SetAttribute("0RTT-Handshake", BooleanValue(true));
            client = startClient();
        });
    }
    else
    {
        Simulator::Schedule(Seconds(0.1), [&client, &startClient]() { client = startClient(); });
    }

    Simulator::Stop(Seconds(stop));
    Simulator::Run();
    Simulator::Destroy();

    const uint64_t expected = g_bytesPerStream * g_streams;
    const bool ok = g_serverRx == expected && g_clientRx == expected;
    std::cout << (ok ? "OK" : "FAIL") << " loss=" << loss << " run=" << run << " streams=" << g_streams
              << " server=" << g_serverRx << " client=" << g_clientRx << " of " << expected << std::endl;
    return ok ? 0 : 1;
}
