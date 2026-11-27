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
└── test/        # ns-3 suites "quic", "quic-features", "quic-wire" and "quic-frames" (see test/TESTS.md), the packet linter and the behaviour oracle
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
- **0-RTT.** With `QuicL4Protocol::0RTT-Handshake` on, a client that already connected to a server sends 0-RTT data right away, behind its Initial packet and within the transport parameters the server announced the last time (kept by the client's `QuicL4Protocol`, RFC 9000, Section 7.4.1; without them it could not open a stream), and the server accepts it while its own handshake runs. The client needs a session ticket for it: the server sends a NewSessionTicket after every handshake, in a CRYPTO frame of a 1-RTT packet, and the client keeps it with the server's parameters; a client that has none does a full handshake even where 0-RTT is allowed, and a server accepts early data only for a ticket it issued. The client's packets carry a 0-RTT header until its handshake completes. The server's stack must allow 0-RTT too (`0RTT-Handshake` on both nodes, as `quic-loss-stress --zrtt` does).

## Loss stress test

`examples/quic-loss-stress.cc` moves `--bytes` bytes on each of `--nstreams` streams in both directions over a link with random loss and exits with 0 only if every byte arrives. Looping it over `--run`, `--loss`, `--rate`, `--delay`, `--zrtt` (a warm-up connection, then a transfer that starts with 0-RTT data), `--vn` (the client proposes a reserved version, so every connection starts with a Version Negotiation round trip), `--cc` (`ns3::QuicCubic`, `ns3::QuicBbr`, `ns3::QuicCongestionControl`), `--msd` and `--md` (the flow-control windows) exercises the loss recovery and the connection set-up: uniform loss up to 15 %, 1 to 4 streams, several links and all three congestion controls complete in every run. `--burst` uses the ns-3 `BurstErrorModel`, which counts packets and not time, so with few packets on the link one burst can last for seconds and a failure at a high burst rate does not point at the protocol.

```bash
./ns3 run "quic-loss-stress --loss=0.05 --run=7 --nstreams=3 --bytes=200000 --cc=ns3::QuicBbr"
```

## Streaming experiment

`examples/quic-video-streaming.cc` sends a video flow, an audio flow and a metadata flow (low-latency live media) over one connection through a bottleneck link, using QUIC or TCP. It prints the one-way delivery delay of every flow, counted from the instant each message was generated. A message that never arrives counts as late.

`scripts/streaming_experiment.py` runs the experiment of the paper.

- Loss is random: uniform at 0 to 3% and in bursts of mean length 4 at 1 to 3%, on an otherwise idle 10 Mbps link, without TLS.
- There are 30 repetitions of five variants: TCP with the ns-3 defaults, TCP with Linux timers and buffers, TCP with those settings and pacing, and QUIC with round-robin and with per-stream FIFO scheduling. The run takes about four minutes.
- The script prints the LaTeX rows of the tables of the paper.

The results directory contains two files for the same experiment.

- `results/streaming-loss.csv` holds the data of the paper, produced by the module as it was at that time (`a4debf5`).
- `results/streaming-loss-v1.1.0.csv` holds the same experiment with release v1.1.0, which contains the loss-recovery corrections of 2026-11-23: the client Handshake is repeated, control frames are covered by the loss timer, RESET_STREAM and STOP_SENDING are retransmitted, CONNECTION_CLOSE is repeated, and retransmissions leave room for an ACK.

The three TCP variants are identical in both files. For QUIC, 574 of the 630 rows per variant differ, by a small amount. The 99th percentile of the video flow drops by about 1 to 10 ms at 1 to 2% loss (for example from 83.4 to 74.1 ms with round-robin at 1% uniform loss). The share of messages later than 150 ms changes by less than 0.2 percentage points, except at 3% uniform loss (from 3.13 to 2.94% with round-robin).

The TCP used is the ns-3 implementation, without tail loss probe or RACK, and there is no cross traffic. The experiment therefore measures the effect of random loss and not of congestion. From the ns-3 root:

```bash
./ns3 build quic-video-streaming
contrib/quic/scripts/streaming_experiment.py run      # writes streaming-loss.csv
contrib/quic/scripts/streaming_experiment.py tables   # rows of the tables
```

## Differences from the RFCs

The frame layouts are those of RFC 9000, Section 19, and the first byte of the headers follows Section 17. What differs:

- **No TLS cryptography:** there is no packet protection and no key update. Every packet ends with a 16-byte tag of zeros, which stands for the AEAD tag so that packets have their real size, and the headers are not protected. The keys are only states: a level becomes available when the handshake message that gives it arrives and is discarded as RFC 9001, Section 4.9 says. `RetryEnabled` on the server's `QuicL4Protocol` makes it answer a first Initial with a Retry packet, and a server gives the client a token in a NEW_TOKEN frame once the handshake completes, which the client puts in its next Initial packet to that server: the tokens are random bytes that the server remembers, and the Retry integrity tag is not computed. `KeyUpdatePackets` (or `InitiateKeyUpdate ()`) makes an end change the Key Phase bit, and the peer follows, as RFC 9001, Section 6 says, without the usage limits of the algorithms.
- **Handshake.** The TLS 1.3 messages (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished) travel in CRYPTO frames of Initial and Handshake packets, as RFC 9001 asks. The messages are built by `QuicTlsEmulator` with the framing and the extensions of the real ones, the QUIC transport parameters and ALPN among them, and with sizes measured with OpenSSL 3.0: the attribute `TlsProfile` selects `ecdsa` (the default), `rsa`, `pq-hybrid` (a ClientHello of about 1.5 KB, which needs two Initial packets) or one of them followed by `+mtls` (the server asks the client for a certificate), and `CertificateChainLength` the number of certificates the server sends. `Alpn` lists the application protocols (`erlang` by default); endpoints that share none fail with CRYPTO_ERROR 0x178. The server answers with an Initial and a Handshake packet in one datagram, expanded to 1200 bytes, and a long chain is held back by the limit of three times what the server received (RFC 9000, Section 8.1). The datagram of an Initial packet is expanded to `InitialPacketSize` bytes (1200 by default) with PADDING frames, and a server discards an Initial packet in a smaller one.
- **Packet numbers.** Initial, Handshake and application data packets have a space of their own, with an ACK, a loss timer and a probe timer for the first two (`quic-socket-handshake.cc`), starting at 0. The loss recovery of the application space is still the single-path one of the module, and the packets of the handshake levels are not counted in the bytes in flight. ACK frames hold 62 bits and the sender's counters 32. Headers are as RFC 9000, Section 17: long headers carry both connection ids, a token in Initial packets and the Length field, the packet number is truncated to 1 to 4 bytes and recovered as in Appendix A, the Fixed Bit and the reserved bits are checked, and Version Negotiation echoes the connection ids of the client. A datagram can hold several packets (RFC 9000, Section 12.2), and the endpoints coalesce the packets of the handshake levels.
- **Connection ids** have `ns3::QuicL4Protocol::ConnectionIdLength` bytes (8 by default, from 1 to 20; zero-length ids are not supported). Each end picks its own id, and the client's first Destination Connection ID is random with at least 8 bytes (RFC 9000, Section 7.2). The connection-id transport parameters (RFC 9000, Section 7.3) are not checked.
- **Frames** follow RFC 9000, Section 19: the frame type is a variable-length integer, error codes have up to 62 bits and a frame that is truncated, of an unknown type or not in its shortest form closes the connection (FRAME_ENCODING_ERROR or PROTOCOL_VIOLATION). Initial and Handshake packets may carry only ACK, CRYPTO, PING, PADDING and CONNECTION_CLOSE frames (Section 12.4); the 0-RTT and 1-RTT packets are not checked against the table yet. The packet number fields of the ACK frame hold 62 bits, and the sender's sent-packet list 32. Stream offsets are 64 bits on the wire; the flow-control limits, windows and buffers of the module are 32 bits.
- **Transport parameters** are the list of RFC 9000, Section 18 (identifier, length and value, with the parameters that have their default value left out), carried in the quic_transport_parameters extension (0x39) of the ClientHello and of EncryptedExtensions, read and checked as the RFC asks and compared with the connection ids of the handshake packets (Section 7.3). `preferred_address` and the extension parameters are not interpreted yet.
- **Datagrams (RFC 9221).** Set `MaxDatagramFrameSize` (0 by default, which takes none) on both ends and call `QuicSocketBase::SendDatagram ()`; `SetDatagramCallback ()` delivers what arrives. A datagram waits in a queue (`DatagramQueueSize` bytes) until the congestion window has room, goes out in one DATAGRAM frame, which is ack-eliciting, and is never sent again when its packet is lost. `GetMaxDatagramSize ()` says how large one can be.
- **Early 1-RTT packets.** A server that is still in its handshake keeps up to 64 of the 1-RTT packets that arrive and processes them when the handshake completes (RFC 9001, Section 5.7), so a lost packet of the client's Finished does not cost the data that follows it.
- **Persistent congestion** is detected as msquic does (a loss after more than 2 consecutive PTOs). The RFC 9002, Section 7.6 duration test is selected with `PersistentCongestionByPto=false`.
- **ACK frequency** follows the ack-frequency draft as msquic does; it asks the peer for an ACK tolerance of up to 41 packets, beyond the one-ACK-per-two-packets of RFC 9000, Section 13.2.2.
- **ECN.** Off by default, as in msquic. `ns3::QuicSocketBase::EnableEcn` makes an endpoint mark its datagrams with ECT(0) (an IP TOS tag on each datagram, so one UDP socket can serve connections with and without ECN), count the ECN codepoints it receives, answer with ACK_ECN frames and respond to an increase of the peer's CE count with a congestion event of the controller, once per recovery epoch. The path is validated (RFC 9000, Section 13.4.2): an ACK that acknowledges marked packets without counts, counts that go down or too few of them stop the marking. ECT(1) is counted but never sent, and the IP layer of this ns-3 has no L4S queue to test it with.
- **Segment size.** `MaxPacketSize` counts the frames of a packet, without the QUIC header and the AEAD tag. The default of 1443 fills a 1500 byte IP MTU exactly (IPv4 20 + UDP 8 + short header 13 + tag 16); the path MTU discovery sizes segments as the IP MTU minus 57. A larger segment makes the IP layer fragment every full datagram. Connection ids longer than 8 bytes make the header longer, and the data of a packet shrinks by the difference so that a packet still fits the MTU.
- **Handshake loss.** The packets of the Initial and Handshake levels are acknowledged and sent again as the RFC 9002 rules say: a packet is lost when one sent three packets later is acknowledged, and the probe timeout (with exponential backoff, and a PING when there is nothing to send again) repeats the CRYPTO data. A client that has nothing in flight keeps the timer armed until HANDSHAKE_DONE arrives, because the server may be held back by its limit of three times.
- **0-RTT.** With `QuicL4Protocol::0RTT-Handshake` on, a client that already connected to a server sends 0-RTT data right away, within the transport parameters the server announced the last time (kept by the client's `QuicL4Protocol`, RFC 9000, Section 7.4.1; without them it could not open a stream). Every packet of the client carries a 0-RTT header until the first answer arrives, so a lost first packet does not leave the server without a connection, and a server that has not yet received the client's parameters holds the writes of its application until it has. The server's stack must allow 0-RTT too (`0RTT-Handshake` on both nodes, as `quic-loss-stress --zrtt` does).

## Known limitations

- Migration is client-initiated only: no `preferred_address` and no multipath.
- **Handshake under heavy loss.** The client repeats its Initial with exponential backoff (about 0.1, 1.1, 3.1, 7.1 and 15.1 s after the start) and gives up when the idle timeout (30 s) expires without an answer: the connection fails, the application hears of it through the connect-failed callback, and nothing more is sent (RFC 9000, Section 10.1). With a loss rate `L` in both directions the chance of that is roughly `(1 - (1 - L)^2)^5`: 0.03% with 10% loss, 0.2% with 15%, 0.6% with 20%, 3.5% with 30% (40 seeds of `quic-loss-stress` at 10, 15, 20, 25 and 30% lost 0, 0, 1, 1 and 1 connections, always the seed whose first five Initials were lost). A shorter idle timeout or a slower backoff would change the chance; the module follows RFC 9002, Section 6.2.
- **Closing.** A connection closed by the application or by the idle timeout stays in the closing state for three PTOs (RFC 9000, Sections 10.1 and 10.2.1), answering the packets of the peer with CONNECTION_CLOSE, as a connection closed by the peer drains for three PTOs.
- **Keep-alive.** Off by default. `KeepAliveInterval` (a `Time`, 0 disables it) sends a PING after that long without receiving a packet; the answer restarts the idle timers of both ends, so a silent connection does not close at the idle timeout. It has no effect when it is not shorter than the idle timeout, and an unreachable peer is still detected (the PING is lost, the probes follow, and the idle timeout or the disconnect timeout closes the connection).
- **Traces.** The `RTO` trace source keeps its initial value of 30 s, and `RTT` reports the latest raw sample, set only when an ACK frees stream data.
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

- Fernando Areias (nando.calheirosx@gmail.com)

## License

This module is distributed under the same license as ns-3, the GNU General
Public License version 2 only (`GPL-2.0-only`). The full text is in
[LICENSE](LICENSE), and every source file carries an SPDX license identifier.
The copyright of the original QUIC implementation belongs to its authors,
listed above and in each file.
