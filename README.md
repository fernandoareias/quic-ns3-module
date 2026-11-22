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
├── examples/    # quic-example, quic-video-streaming
├── scripts/     # streaming_experiment.py
├── results/     # streaming-uniform-loss.csv
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

## Streaming experiment

`examples/quic-video-streaming.cc` sends a video, an audio and a metadata flow (low-latency live media) over one connection through a bottleneck link, with QUIC or TCP, and prints the one-way delivery delay of every flow, counted from the instant each message was generated; a message that never arrives counts as late. `scripts/streaming_experiment.py` runs the experiment of the paper (uniform random loss of 0 to 3 % on an otherwise idle 10 Mbps link, no TLS, 30 repetitions of five variants: TCP with the ns-3 defaults, with Linux timer values and with Linux values plus pacing, and QUIC with round-robin and with per-stream FIFO scheduling, about two minutes) and prints the LaTeX rows of its tables; the results it produced are in `results/streaming-uniform-loss.csv`. There is no cross traffic, so the experiment measures random loss and not congestion. From the ns-3 root:

```bash
./ns3 build quic-video-streaming
contrib/quic/scripts/streaming_experiment.py run      # writes streaming-uniform-loss.csv
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

## Known limitations

- Migration is client-initiated only: no `preferred_address` and no multipath.
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

GNU General Public License v2.0 — see individual source files for full license headers.
