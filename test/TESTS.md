# Test evidence map

Two suites, 103 test cases, all passing:

```
./ns3 build
build/utils/ns3-dev-test-runner-debug --suite=quic          --verbose   # 46 cases, quic-test-suite.cc
build/utils/ns3-dev-test-runner-debug --suite=quic-features --verbose   # 57 cases, quic-features-test-suite.cc
```

A third suite, `quic-gaps` (`quic-gaps-test-suite.cc`), holds reproductions of conformance gaps that
are not fixed yet. Its cases do nothing unless `QUIC_GAPS` is set (`1` for all of them, or a list of
case names), so the suite passes; see the comment at the top of the file.

Two tools check the module from outside the test runner:

- `test/oracle.sh` runs 34 short scenarios and compares a hash of every packet they send with the
  recorded one (`test/oracle.expected`). It is for refactors that must not change the behaviour and
  stops being valid when the wire format changes on purpose.
- `test/tools/quic_pcap_lint.py` (self-test: `python3 -I test/tools/test_quic_pcap_lint.py`) checks the
  QUIC packets of pcap files against RFC 8999, RFC 9000 and RFC 9001, rule by rule;
  `test/tools/lint_examples.sh` runs it on the pcaps of the examples.

`doc/CONFORMANCE.md` lists, section by section, what the module does of each RFC and draft.

A suite stops at its first failing case, so the cases after it are not run until it is fixed.

| Feature | Evidence (test case) |
|---|---|
| Frame and error code wire values (RFC 9000 s19, s20) | `quic`: frame type values, aliases, STREAM encoding, IsStream, error codes |
| ACK, ACK_FREQUENCY, IMMEDIATE_ACK, NEW/RETIRE_CONNECTION_ID, MAX_STREAMS, STREAMS_BLOCKED, RESET_STREAM, STOP_SENDING, PATH_CHALLENGE/RESPONSE, MAX_DATA, MAX_STREAM_DATA serialization | `quic-features`: the five `wire:` cases |
| Transport parameters (min_ack_delay, stateless reset token, migration allowed) | `quic-features`: transport parameters round trip |
| Spin bit, active_connection_id_limit, stateless reset token | `quic`: RFC 9000 s17.3.1 / s18.2 cases |
| Loss detection, persistent congestion (RFC 9002), msquic CUBIC (loss, spurious undo, PTO based persistent congestion) | `quic`: RFC 9002 cases, CUBIC events, reordering undo |
| CUBIC without HyStart, BBR, NewReno available | `quic-features`: congestion control defaults |
| End-to-end transfer with CUBIC, BBR, NewReno under no loss, 2-3% uniform loss and burst loss, no corrupted bytes | `quic-features`: `end-to-end: ...` (7 cases); `quic`: end-to-end 0/2/5% |
| Flow control (small windows), STOP_SENDING | `quic`: small flow-control windows, STOP_SENDING (also under loss) |
| A stream turned away by a full socket transmit buffer is woken when the socket sends packets | `quic-features`: the two `send path:` cases (one stream, three streams) |
| Receive buffers are never overflowed by the window the receiver advertises, and acknowledged data is never dropped | `quic-features`: the two `flow control:` cases (stream buffer, socket buffer) |
| The ACK tolerance asked of the peer follows the congestion window (several ACKs per round trip), so light loss at high speed is not throttled | `quic-features`: ack frequency: the tolerance asked of the peer follows the window |
| No IP fragmentation: data plus the ACK frame fit in the segment | `quic-features`: datagrams: data plus the ACK frame never exceed the segment size |
| Throughput efficiency | `quic-features`: 3 MB over 10 Mbps finishes within 4.5 s |
| Delayed ACK (tolerance 2) and ACK_FREQUENCY (tolerance 41 on fast paths) | `quic-features`: delayed ACK; `quic`: ACK_FREQUENCY |
| Stream schedulers: FIFO, per-stream FIFO (msquic default), priority FIFO, round-robin (conservation, fairness, FIFO wait) | `quic-features`: scheduler cases and the two latency cases; `quic`: FIFO, RR, priority |
| Loss recovery with the connection kept open (3% loss, server never closes, all streams complete) | `quic-features`: loss recovery: 3% loss, server never closes |
| Stream ids per RFC 9000, MAX_STREAMS, stream credit | `quic`: stream ids / limits / credit |
| Writes during the handshake queued and bounded | `quic-features`: handshake write, pending write bound |
| Close behaviour: no CONNECTION_CLOSE ping-pong after close | `quic-features`: close terminates |
| Several connections on one listener, one after another and starting together (CID demultiplexing, per-connection scheduler, full handshake for a known server) | `quic-features`: the two `four connections` cases |
| Stateless reset | `quic`: stateless reset |
| Connection migration, path validation, CC reset on address change, port rebinding | `quic`: the two migration cases |
| Destination CID update after idle | `quic`: connection id changes after an idle period |
| Path MTU discovery (1500 and capped path) | `quic`: the two MTU cases |
| Idle timeout, disconnect timeout, outages | `quic`: idle timeout, blackout cases |
| RTT samples: ack delay in microseconds, capped at `max_ack_delay`, never below `min_rtt`; `min_rtt` and raw `latest_rtt` (RFC 9002 s5) | `quic-features`: RTT samples |
| ACK delay divided by 2^`ack_delay_exponent` on the wire (RFC 9000 s19.3) | `quic-features`: ACK frames carry the ack delay divided by 2^ack_delay_exponent |
| Packet threshold: 3 numbers below an acknowledged packet is lost, 2 is not (RFC 9002 s6.1.1) | `quic-features`: loss detection |
| First PTO is 3 * kInitialRtt + `max_ack_delay` after the packet; the second probe is a PING (RFC 9002 s6.2) | `quic-features`: the two `PTO:` cases |
| Spin bit flips once per round trip (RFC 9000 s17.4) | `quic-features`: spin bit |
| `max_idle_timeout` 0 means no limit, minimum of the two otherwise (RFC 9000 s10.1) | `quic-features`: the two `idle timeout:` cases |
| Draining after a CONNECTION_CLOSE from the peer: the application hears at once, the state stays three PTOs (RFC 9000 s10.2.2) | `quic-features`: draining |
| HANDSHAKE_DONE is retransmitted when lost (RFC 9000 s13.3) | `quic-features`: HANDSHAKE_DONE is sent again |
| Version Negotiation in network byte order, client retries with a supported version (RFC 9000 s6) | `quic-features`: version negotiation |
| Transport parameter ranges (`ack_delay_exponent` 20 accepted, 25 rejected) (RFC 9000 s18.2) | `quic-features`: the two `transport parameters:` cases |
| Frame bytes as RFC 9000 s19 (ACK ranges, error codes, CONNECTION_CLOSE, NEW_CONNECTION_ID) and header first bytes as s17 | `quic-features`: the two `wire:` byte-layout cases |
| A server that announces `disable_active_migration` is not migrated (RFC 9000 s18.2) | `quic`: the third migration case |
| Path validation survives a lost PATH_CHALLENGE (one, two or three in a row) or a lost PATH_RESPONSE when the server has nothing in flight; the first packet on the new path is at least 1200 bytes | `quic`: the five `path validation` cases |

## Defects found while writing these tests (fixed)

1. After a close with `FlushOnClose` both endpoints answered every CONNECTION_CLOSE with another one, forever
   (about 15 packets per second until the end of the simulation).
   Now closing sends one CONNECTION_CLOSE and ignores the rest; the peer drains at once (RFC 9000 s10.2).
2. A client that already knew a server went to a "fast connect" path the server never accepted, so a second
   connection from the same node never completed. A known server now gets a full handshake unless 0-RTT is enabled.
3. `SendStatelessReset` indexed past its buffer for short packets (crash).
4. Connections accepted by one listener shared a single transmit scheduler (the copied buffer kept the listener's
   scheduler pointer), so when handshakes overlapped one connection sent another connection's queued stream frames
   and the receiver aborted with a flow-control error. Every accepted connection now has its own scheduler.
   Covered by `quic-features`: four connections starting together on one listener complete.
5. The ACK frame was appended to a datagram that already held a full segment of stream frames, so every full
   packet carrying an ACK went over the MTU and IP fragmented it (a lost fragment cost the whole packet, which
   cut throughput under random loss). Around packet 66 thousand the reassembled datagram also arrived with its
   tail overwritten, the ACK frame was undecodable and the connection hung at 96 MB. The room for the ACK is now
   reserved before the stream frames are chosen, and the packet that is kept for retransmission is copied before
   the ACK is appended. Splitting a stream frame also sizes the new header (it always carries a length).
   Covered by `quic-features`: datagrams: data plus the ACK frame never exceed the segment size.
6. A stream whose frame was refused by a full socket transmit buffer put it back and stopped, and nothing woke it
   again: the wake-ups come from application writes, MAX_STREAM_DATA and MAX_DATA. With a small window those
   arrive all the time and hide the problem, but with a large window and an application that had already
   written everything (the last 4 MiB sat in the stream buffer) the sender went idle for good, with the data
   unsent and the window wide open (a 50 MB transfer at 0.5% loss stopped at about 46 MB in 4 runs out of 10).
   The socket now tells the stream layer when it has sent packets and made room, and the streams that were turned
   away try again. Covered by `quic-features`: send path: stream data held back by a full socket buffer is sent
   once the buffer drains.
7. The stream receive window grows up to 16 MiB (auto-tuning) while the stream receive buffer was 4 MiB, so after
   a burst of losses (about 960 packets at the end of slow start on a 1 Gbps path) the out-of-order data did not
   fit, and the receiver aborted the connection with `NO_ERROR` ("Aborting connection due to full RX buffer"), which
   the sender saw as a normal close with cwnd 0 (a 200 MB transfer stopped at 21 MB). The receive buffer now grows
   to hold the window it advertises, as in msquic, so a peer that respects flow control cannot overflow it.
   Covered by `quic-features`: flow control: a stream buffer smaller than the advertised window is never overflowed.
8. The socket receive buffer (4 MiB) dropped, without any error, a whole chunk of stream data that did not fit. When a
   hole is filled the stream releases all the out-of-order data it held at once (up to the window), the data had
   already been acknowledged and counted by flow control, and the application then saw a stream with a gap (2.6 MB
   delivered out of 3 MB, corrupted). Acknowledged data is no longer dropped; the buffer size is only a notional limit.
   Covered by `quic-features`: flow control: a socket buffer smaller than the advertised window never drops
   acknowledged data.
9. The sender asks the peer to acknowledge only every 41st packet (ACK_FREQUENCY, as msquic does) once a flush is
   limited by scheduling, and only lowered it on persistent congestion. After a loss the window shrinks, but the
   tolerance stayed at 41: with a window smaller than that the peer could only acknowledge on its 25 ms delayed-ACK
   timer, the ACK clock stalled and throughput under light loss fell to 0.7 to 0.9 times that of TCP at 100 Mbps and
   1 Gbps (a 20 MB transfer at 100 Mbps with 0.1% loss: 6.9 s instead of 4.6 s, with the tolerance above what the
   window supports in 93% of the time). The tolerance is now at most the window in packets divided by
   `AckToleranceCwndDivisor` (8 by default; 0 restores msquic's batch size + 1), checked before every send, so
   it follows the window down. Transfers with a large window keep the thinning: the simulator's CPU for a lossless
   127 MB transfer at 100 Mbps changes by 2%. Covered by `quic-features`: ack frequency: the tolerance asked of the
   peer follows the window.
10. The ACK delay was sent in microseconds without the `ack_delay_exponent`, and the NewReno/CUBIC receiver read it as
    nanoseconds (BBR and the legacy path read it right), so RTT samples were never corrected by the delay. The
    minimum RTT started at 0 and `min()` kept it there for ever, so the CUBIC target window never got the `+ min_rtt`
    term and the "not below min_rtt" guard of RFC 9002 s5.3 could not work. Both fixed; `max_ack_delay` is the
    peer's parameter and no longer follows the largest delay seen.
    Covered by `quic-features`: RTT samples, ACK frames carry the ack delay divided by 2^ack_delay_exponent.
11. The PTO was armed from the moment the timer was set instead of from the last ack-eliciting packet, started at
    2 * kInitialRtt (RFC 9002: 3 *) before the first sample, used 2 * srtt in the handshake and its "then a PING"
    probe sent an empty packet that does not ask for an ACK. Fixed.
    Covered by `quic-features`: the two `PTO:` cases.
12. `max_idle_timeout` 0 on either side made the timer expire at once (minimum with 0), and the unit was the second.
    Now milliseconds, 0 means no limit, and the timer never runs below three PTOs.
    Covered by `quic-features`: the two `idle timeout:` cases.
13. The spin bit was copied by both endpoints and never flipped; HANDSHAKE_DONE and the MAX_DATA answering
    DATA_BLOCKED went out of the transmit buffer and were never resent; a CONNECTION_CLOSE from the peer dropped the
    connection state at once; the Version Negotiation list was little-endian. Fixed.
    Covered by `quic-features`: spin bit, HANDSHAKE_DONE, draining, version negotiation.
14. With the draining state, the stream-0 send loop of `SendPendingData` never ended when a frame stayed queued (the
    send refused it for ever). It now stops when the send reports the draining state. Found by the
    `ack_delay_exponent 25` case, whose client receives a CONNECTION_CLOSE in the middle of the handshake.
15. After a client migration the server may send only three times what it receives on the new path until the path is
    validated. The client's probe was a bare PING (a few bytes), so the server's allowance was enough for one
    PATH_CHALLENGE; data then took what was left, and a challenge (or its response) that was lost could not be
    repeated. With the server idle and no packet from the client to replenish the allowance, the validation timed
    out, every path was gone and the server closed the connection (1 run in 200 of the streaming scenario with a path
    change and 1% loss). The probe is now expanded to 1200 bytes (RFC 9000 s8.2.1), which gives the server 3600 bytes
    of allowance, and data leaves the last 152 bytes of an unvalidated path alone while a challenge is pending.
    The size of a challenge is also counted with its header now (it used to overshoot the allowance by the header).
    Covered by `quic`: the five `path validation` cases (a receive error model drops the first PATH_CHALLENGE or
    PATH_RESPONSE packets by parsing PPP, IPv4, UDP and the QUIC frame).
