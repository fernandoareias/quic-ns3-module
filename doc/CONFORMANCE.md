# Conformance matrix

What the module does of each RFC and draft of the IETF QUIC working group, section by section. The
status is the state of the module on the branch `rfc-alignment` at the start of the alignment work
(2026-11-26), taken from reading the code and from the test suites. The last column names the phase
of the plan that closes the item. A row is updated, with the test that shows it, when its phase
ends.

Status: **done** follows the document; **partial** follows it in part; **divergent** does something
else; **missing** is not implemented; **n/a** does not apply to a simulator.

Evidence: a test case of the suites `quic` and `quic-features` (see `test/TESTS.md`), a rule of the
packet linter (`test/tools/quic_pcap_lint.py`) or a case of `quic-wire` and `quic-frames`.

## RFC 8999 (invariants)

| Section | Requirement | Status | Phase | Note |
|---|---|---|---|---|
| 5.1 | Long header: form bit, version, connection id lengths and ids | done | | quic-wire: header vectors |
| 5.2 | Short header: form bit, destination id of agreed length | done | | quic-wire: header forms |
| 5.4 | Version Negotiation packet | done | | quic-wire: header forms; quic-features: version negotiation |
| 6 | The client ignores a Version Negotiation packet that lists its version | done | | quic-loss-stress `--vn` |

## RFC 9000 (transport)

| Section | Requirement | Status | Phase | Note |
|---|---|---|---|---|
| 2, 3 | Streams: ids, types, send and receive states | partial | F4 | The receive states follow Section 3.2 (quic-streams); the send side does not reach DATA_RECVD or RESET_RECVD, because the ACKs are not tied to streams |
| 4.1, 4.2 | Flow control per stream and per connection | partial | F4 | Credit advances on in-order delivery, not on `Recv()`; the limits of the module are 32 bits |
| 4.5 | Final size | done | | quic-streams: offset plus length, copies after DATA_READ, RESET_STREAM after the data |
| 5.1 | Connection ids: variable length, NEW and RETIRE_CONNECTION_ID | partial | F3 | Each end has its own id of 1 to 20 bytes (quic-features: connection ids); the NEW_CONNECTION_ID codec still stores the id as given |
| 5.2 | Receiving packets: demultiplexing by connection id | partial | F5 | IPv4 only; no zero-length ids |
| 6 | Version negotiation | partial | F9 | The client discards a list that holds its version; with no common version it sends CONNECTION_CLOSE instead of abandoning the attempt in silence |
| 7.2 | The client picks a random Destination Connection ID of at least 8 bytes; the server picks its own id | done | | quic-features: connection ids |
| 7.3 | Authenticating connection ids with transport parameters | partial | F7 | Checked for initial_source and original_destination (the handshake data is not authenticated); no Retry |
| 7.4 | Transport parameters; remembering them for 0-RTT | done | | quic-wire: RFC 9001 appendix A.2, defaults, invalid values; the client remembers them for 0-RTT |
| 8.1 | Address validation: Retry, NEW_TOKEN, 3x amplification limit | partial | F7 | Limit on the server only; no Retry, no tokens |
| 8.2 | Path validation | done | | quic: migration cases |
| 9 | Connection migration | partial | F7, F11 | Client-initiated only; no `preferred_address` |
| 10.1 | Idle timeout | done | | quic: idle timeout cases |
| 10.2 | Closing and draining | done | | |
| 10.3 | Stateless reset | done | | quic: stateless reset |
| 11 | Error handling | partial | F4 | Malformed frames and unknown types close the connection (quic-frames); the stream-level errors of Section 4.5 are still to do |
| 12.2 | Coalescing packets | missing | F5 | |
| 12.3 | Packet numbers: one space per encryption level | divergent | F7 | One counter for all; the header truncates and recovers them as in Appendix A |
| 12.4 | Frames allowed in each packet type | missing | F3 | STREAM frames travel in Initial and Handshake packets |
| 13.2 | Generating acknowledgements | done | | quic-features: delayed ACK |
| 13.4 | ECN | missing | F8 | `ACK_ECN` closes the connection |
| 14.1 | Initial datagrams of at least 1200 bytes | partial | F5 | By padding inside STREAM, not with PADDING frames; the datagram is longer than 1200 bytes |
| 14.3 | Path MTU discovery | partial | F5 | msquic-style search; no black-hole detection |
| 15 | Versions; reserved versions | partial | F9 | Version 2 is only in the header codec |
| 16 | Variable-length integers | done | | quic-wire: Appendix A.1 |
| 17.2 | Long header packets | done | | quic-wire: RFC 9001 appendix A.2, A.3 |
| 17.2.5 | Retry | partial | F7 | The header is done (quic-wire: A.4); no endpoint sends or handles it |
| 17.3 | Short header packets | done | | quic-wire: header forms |
| 17.4 | Spin bit | done | | quic: spin bit; the `SpinBit` attribute turns it off (random values), the one-in-16 policy is left to the application |
| 18.2 | Transport parameters | partial | F7 | All but preferred_address (F11) and the extension parameters (F9); carried behind the handshake pseudo-stream until F7 |
| 19.1 to 19.2 | PADDING, PING | done | | quic-frames |
| 19.3 | ACK | done | | quic-frames: bytes, invalid ranges |
| 19.3.2 | ACK with ECN counts | partial | F8 | Codec done and accepted on receipt (quic-frames); nothing sends or counts ECN yet |
| 19.4, 19.5 | RESET_STREAM, STOP_SENDING | done | | quic-frames: 62-bit error codes |
| 19.6, 19.7 | CRYPTO, NEW_TOKEN | partial | F7 | Codecs done (quic-frames); no endpoint sends them |
| 19.8 | STREAM | done | | quic-frames: LEN, OFF and FIN bits; a length of zero is zero; the sender always writes LEN |
| 19.9 to 19.14 | MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, *_BLOCKED | done | | |
| 19.15, 19.16 | NEW_CONNECTION_ID, RETIRE_CONNECTION_ID | done | | quic-frames: ids of 1 to 20 bytes |
| 19.17, 19.18 | PATH_CHALLENGE, PATH_RESPONSE | done | | |
| 19.19, 19.20 | CONNECTION_CLOSE, HANDSHAKE_DONE | done | | quic-frames |
| 20 | Error codes | partial | F3, F4 | |

## RFC 9001 (TLS)

| Section | Requirement | Status | Phase | Note |
|---|---|---|---|---|
| 4 | CRYPTO frames carry the TLS handshake | missing | F7 | The handshake is a padded STREAM payload |
| 4.1.2 | The handshake is confirmed by HANDSHAKE_DONE | divergent | F8 | The client confirms on its first Handshake packet |
| 4.6 | 0-RTT with session tickets | divergent | F7 | A flag, not a ticket |
| 4.9 | Discarding Initial and Handshake keys | divergent | F7 | |
| 5 | Packet protection (size: 16-byte tag) | partial | F5 | The tag is there (zeros) and counted in the path MTU; the cryptography stays emulated |
| 5.8 | Retry integrity tag | missing | F7 | |
| 6 | Key update | missing | F7 | |
| 8.1 | ALPN | missing | F7 | |

## RFC 9002 (recovery)

| Section | Requirement | Status | Phase | Note |
|---|---|---|---|---|
| 5 | RTT estimation | divergent | F8 | Samples only from ACKs that free stream data |
| 6.1 | Packet and time thresholds | partial | F8 | A hole when the largest acknowledged packet is not in the sent list |
| 6.2 | Probe timeout | partial | F8 | One timer for all spaces; no per-space backoff |
| 6.4 | Discarding a packet number space | divergent | F7, F8 | |
| 7.1 to 7.4 | NewReno, slow start, recovery | done | | quic: RFC 9002 cases |
| 7.6 | Persistent congestion | partial | F8 | msquic rule by default; the RFC rule with `PersistentCongestionByPto=false` |
| 7.7 | Pacing | partial | | msquic scheme |
| 7.8 | Application-limited sender | divergent | | msquic rule in CUBIC |
| 2 | bytes_in_flight counts every packet in flight | divergent | F8 | Only the payload of STREAM frames |
| B.7 | ECN-CE as a congestion signal | missing | F8 | |

## Extensions and drafts

| Document | Status | Phase |
|---|---|---|
| RFC 9221 DATAGRAM | missing | F9 |
| RFC 9287 GREASE bit | missing | F9 |
| RFC 9368 compatible version negotiation | missing | F9 |
| RFC 9369 QUIC version 2 | missing | F9 |
| RFC 10069 Multipath | missing | F11 |
| RFC 9438 CUBIC | partial (three divergences) | F8 |
| RFC 9406 HyStart++ | done (off by default) | |
| RFC 8899 DPLPMTUD | partial | F5 |
| draft-ietf-quic-reliable-stream-reset-11 | missing | F9 |
| draft-ietf-quic-ack-frequency-14 | partial (the frames are done; the threshold is off by one) | F9 |
| draft-ietf-quic-receive-ts-04 | missing | F10 |
| draft-ietf-quic-qlog-main-schema-15, quic-events-14 | missing | F6 |
| draft-ietf-ccwg-bbr-07 (BBRv3) | missing (the module has BBRv1) | F10 |
| RFC 9308, 9312 (applicability, manageability) | checklist at the end of the work | F12 |
| RFC 9114, 9204 (HTTP/3, QPACK), draft-ietf-quic-address-discovery, load-balancers, extended-key-update, qmux, retry-offload | out of scope | |

## Linter baseline

`test/tools/lint_examples.sh` on the pcaps of `quic-example`, `erldp-transport-comparison` and
`epmd-simulator-quic` (2026-11-26, 663 datagrams): 1129 violations, of them R-hdr-04 30, R-hdr-05
147, R-frame-02 484, R-frame-04 2 and R-hs-02 466. The count is a lower bound, because a packet that
cannot be parsed hides the rules that would follow. It goes to zero as the phases F2 to F8 close.
