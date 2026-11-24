# QUIC Module for ns-3

An ns-3 contrib module implementing the **QUIC transport protocol**, forked from [signetlabdei/quic](https://github.com/signetlabdei/quic) and updated to follow RFC 9000 and RFC 9002. [msquic](https://github.com/microsoft/msquic) is the reference for the defaults the RFCs leave open.

## Features

- **Streams:** RFC 9000 stream ids, flow control per stream and per connection, `RESET_STREAM`, `STOP_SENDING`, stream credit with `MAX_STREAMS`.
- **Congestion control:** CUBIC (default, RFC 9438, with pacing), NewReno and BBR.
- **Loss recovery (RFC 9002):** packet and time thresholds, probe timeout, persistent congestion.
- **Stream schedulers:** per-stream FIFO (default), round-robin, priority FIFO, EDF and per-frame FIFO, selected with `SchedulingPolicy`.
- **Connections:** connection ids, client-initiated migration with path validation, stateless reset, path MTU discovery.
- **ACK frequency:** `ACK_FREQUENCY` and `IMMEDIATE_ACK`.
- **Traces:** congestion window, RTT, spurious loss, stream reset and packet transmit/receive.

## RFC compliance

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC transport | Behaviour and frame layouts follow the RFC; the packet headers only in part, see [Differences from the RFCs](#differences-from-the-rfcs) |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | Loss detection and congestion control | Followed, with one msquic default that can be switched |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to secure QUIC | Not implemented: no TLS, no packet protection, no key update |
| [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438) | CUBIC | Default congestion control |

## Module structure

```
contrib/quic/
├── model/       # protocol stack: sockets, L4/L5 protocols, streams, headers and frames,
│                #   transport parameters, buffers, stream schedulers, NewReno / CUBIC / BBR
├── helper/      # QuicHelper (InstallQuic)
├── examples/    # quic-example, quic-video-streaming, quic-loss-stress
├── scripts/     # streaming_experiment.py
├── results/     # streaming-loss.csv
└── test/        # two ns-3 suites, "quic" and "quic-features" (see test/TESTS.md)
```

## Building and running

The module needs ns-3 with CMake support. From the ns-3 root:

```bash
./ns3 configure --enable-examples --enable-tests
./ns3 build
./ns3 run quic-example
```

Tests (debug build):

```bash
build/utils/ns3-dev-test-runner-debug --suite=quic
build/utils/ns3-dev-test-runner-debug --suite=quic-features
```

`test/TESTS.md` maps each feature to the test case that covers it.

## Using the module from an application

```cpp
QuicHelper quic;
quic.InstallQuic(nodes);                        // instead of InternetStackHelper
Ptr<Socket> socket = Socket::CreateSocket(node, QuicSocketFactory::GetTypeId());
```

- **Stream limits.** Like msquic, the module lets the peer open no stream until the application allows some: `MaxStreamIdBidi` and `MaxStreamIdUni` default to 0. An application that never raises them hangs after the handshake (`STREAMS_BLOCKED`). Set them with `Config::SetDefault("ns3::QuicSocketBase::MaxStreamIdBidi", UintegerValue(n))` or per socket with `SetAttribute`, on both ends.
- **Default stream.** `Socket::Send(packet)` writes on the first bidirectional stream the endpoint opens: stream 0 on the client and stream 1 on the server (RFC 9000 stream ids), so both ends need a stream allowance. `Socket::Send(packet, streamId)` picks the stream.
- **0-RTT.** A client that already knows a server still gets a full handshake. Set `ns3::QuicL4Protocol::0RTT-Handshake` on the client's `QuicL4Protocol` to connect with 0-RTT; the server accepts it from addresses it has authenticated.

## Loss stress test

`examples/quic-loss-stress.cc` moves `--bytes` bytes on each of `--nstreams` streams in both directions over a link with random loss and exits with 0 only if every byte arrives. Looping it over `--run`, `--loss`, `--rate`, `--delay`, `--zrtt` (a warm-up connection, then a transfer that starts with 0-RTT data), `--vn` (the client proposes a reserved version, so every connection starts with a Version Negotiation round trip), `--cc` (`ns3::QuicCubic`, `ns3::QuicBbr`, `ns3::QuicCongestionControl`), `--msd` and `--md` (the flow-control windows) exercises the loss recovery and the connection set-up: uniform loss up to 15 %, 1 to 4 streams, several links and all three congestion controls complete in every run. `--burst` uses the ns-3 `BurstErrorModel`, which counts packets and not time, so with few packets on the link one burst can last for seconds and a failure at a high burst rate does not point at the protocol.

```bash
./ns3 run "quic-loss-stress --loss=0.05 --run=7 --nstreams=3 --bytes=200000 --cc=ns3::QuicBbr"
```

## Streaming experiment

`examples/quic-video-streaming.cc` sends a video, an audio and a metadata flow (low-latency live media) over one connection through a bottleneck link, with QUIC or TCP, and prints the one-way delivery delay of every flow, counted from the instant each message was generated; a message that never arrives counts as late. `scripts/streaming_experiment.py` runs the experiment of the paper: random loss (uniform at 0 to 3 % and in bursts of mean length 4 at 1 to 3 %) on an otherwise idle 10 Mbps link, no TLS, 30 repetitions of five variants (TCP with the ns-3 defaults, with Linux timers and buffers, and with those plus pacing, and QUIC with round-robin and with per-stream FIFO scheduling, about four minutes) and prints the LaTeX rows of its tables. The results it produced are in `results/streaming-loss.csv`. That file is the data of the paper, from the module as it was at that time (`a4debf5`); `results/streaming-loss-v1.1.0.csv` is the same experiment with the module of release v1.1.0, which has the loss-recovery corrections of 2026-11-23 (client Handshake repeated, control frames covered by the loss timer, RESET_STREAM/STOP_SENDING retransmitted, CONNECTION_CLOSE repeated, ACK room in retransmissions). The three TCP variants are identical in both files; for QUIC 574 of the 630 rows per variant differ, by little: the 99th percentile of the video flow drops by about 1 to 10 ms at 1 to 2 % loss (for example 83.4 to 74.1 ms with round-robin at 1 % uniform loss) and the share of messages later than 150 ms changes by under 0.2 points, except at 3 % uniform loss (3.13 to 2.94 % with round-robin). The TCP is the ns-3 one, without tail loss probe or RACK, and there is no cross traffic, so the experiment measures random loss and not congestion. From the ns-3 root:

```bash
./ns3 build quic-video-streaming
contrib/quic/scripts/streaming_experiment.py run      # writes streaming-loss.csv
contrib/quic/scripts/streaming_experiment.py tables   # rows of the tables
```

## Differences from the RFCs

The frame layouts are those of RFC 9000 §19, and the first byte of the headers follows §17. What differs:

- **No TLS:** no packet protection, no key update, no CRYPTO frames, no Retry and no address-validation tokens (`NEW_TOKEN` is ignored by clients and is a protocol violation for servers).
- **Long headers** carry no Source Connection ID, Token or Length, and the packet number is always 4 bytes (32 bits, not 62).
- **Connection ids** are always 8 bytes, and the connection-id transport parameters (RFC 9000 §7.3) are not checked. `OmitConnectionId` (short headers without the id) is flagged in a reserved bit.
- **Transport parameters** are a fixed 72-byte structure, not the TLV list of RFC 9000 §18, carried in the handshake payload.
- **Persistent congestion** is detected as msquic does (a loss after more than 2 consecutive PTOs). The RFC 9002 §7.6 duration test is selected with `PersistentCongestionByPto=false`.
- **ACK frequency** follows the ack-frequency draft as msquic does; it asks the peer for an ACK tolerance of up to 41 packets, beyond the one-ACK-per-two-packets of RFC 9000 §13.2.2.
- No ECN marking (only the `ACK_ECN` counts are read) and no coalesced packets.
- **Segment size.** `MaxPacketSize` counts the frames of a packet, without the QUIC header. The default of 1459 fills a 1500 byte IP MTU exactly (IPv4 20 + UDP 8 + short header 13); the path MTU discovery sizes segments as the IP MTU minus 41. A larger segment makes the IP layer fragment every full datagram.
- **Handshake loss.** The Handshake packet of the client is what lets the server leave `CONNECTING_SVR`; the client repeats it (with a PING, in a Handshake header, with exponential backoff) until it receives HANDSHAKE_DONE (RFC 9001 §4.9.2). A server that is already open treats the repeated packet like any other and acknowledges it.
- **0-RTT.** With `QuicL4Protocol::0RTT-Handshake` on, a client that already connected to a server sends 0-RTT data right away, within the transport parameters the server announced the last time (kept by the client's `QuicL4Protocol`, RFC 9000 s7.4.1; without them it could not open a stream). Every packet of the client carries a 0-RTT header until the first answer arrives, so a lost first packet does not leave the server without a connection, and a server that has not yet received the client's parameters holds the writes of its application until it has. The server's stack must allow 0-RTT too (`0RTT-Handshake` on both nodes, as `quic-loss-stress --zrtt` does).

## Known limitations

- Migration is client-initiated only: no `preferred_address` and no multipath.
- **Handshake under heavy loss.** The client repeats its Initial with exponential backoff (about 0.1, 1.1, 3.1, 7.1 and 15.1 s after the start) and gives up when the idle timeout (30 s) expires without an answer: the connection fails, the application hears of it through the connect-failed callback, and nothing more is sent (RFC 9000 s10.1). With a loss rate `L` in both directions the chance of that is roughly `(1 - (1 - L)^2)^5`: 0.03% with 10% loss, 0.2% with 15%, 0.6% with 20%, 3.5% with 30% (40 seeds of `quic-loss-stress` at 10, 15, 20, 25 and 30% lost 0, 0, 1, 1 and 1 connections, always the seed whose first five Initials were lost). A shorter idle timeout or a slower backoff would change the chance; the module follows RFC 9002 s6.2.
- **Closing.** A connection closed by the application or by the idle timeout stays in the closing state for three PTOs (RFC 9000 s10.1, s10.2.1), answering the packets of the peer with CONNECTION_CLOSE, as a connection closed by the peer drains for three PTOs.
- No keep-alive.
- Loopback support requires special handling due to ns-3's UDP socket internals.

## Original authors

[SIGNET Lab](https://github.com/signetlabdei), Department of Information Engineering, University of Padova:

- Alvise De Biasio
- Federico Chiariotti
- Michele Polese
- Davide Marcato
- Umberto Paro

## Fork maintainer

RFC 9000 / RFC 9002 updates and ns-3 integration patches:

- Fernando Areias — nando.calheirosx@gmail.com

## License

This module is distributed under the same license as ns-3, the GNU General
Public License version 2 only (`GPL-2.0-only`). The full text is in
[LICENSE](LICENSE), and every source file carries an SPDX license identifier.
The copyright of the original QUIC implementation belongs to its authors,
listed above and in each file.
