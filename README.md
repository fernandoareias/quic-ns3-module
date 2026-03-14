# QUIC Module for ns-3

An ns-3 contrib module implementing the **QUIC transport protocol**, forked from [signetlabdei/quic](https://github.com/signetlabdei/quic) and updated to improve RFC compliance.

---

## Overview

This module provides a simulation-ready QUIC stack for ns-3.

### RFC Compliance

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | Supported |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | Supported |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | Partial — TLS-related features are not implemented due to ns-3 limitations |

> Implementation is based on [msquic](https://github.com/microsoft/msquic) and the official RFCs. Features requiring TLS integration (RFC 9001) are not supported.

---

## Module Structure

```
contrib/quic/
├── model/              # Core QUIC protocol stack
│   ├── quic-socket.{cc,h}              # Abstract QUIC socket
│   ├── quic-socket-base.{cc,h}         # Main socket implementation
│   ├── quic-l4-protocol.{cc,h}         # L4 protocol (UDP-based)
│   ├── quic-l5-protocol.{cc,h}         # Stream multiplexing layer
│   ├── quic-stream{,-base}.{cc,h}      # Stream abstraction
│   ├── quic-header.{cc,h}              # QUIC packet headers
│   ├── quic-subheader.{cc,h}           # QUIC frame subheaders
│   ├── quic-transport-parameters.{cc,h}# Transport parameter negotiation
│   ├── quic-socket-{rx,tx}-buffer.{cc,h} # Socket-level buffers
│   ├── quic-stream-{rx,tx}-buffer.{cc,h} # Stream-level buffers
│   ├── quic-socket-tx-scheduler.{cc,h} # Base TX scheduler
│   ├── quic-socket-tx-edf-scheduler.{cc,h}   # EDF scheduler
│   ├── quic-socket-tx-pfifo-scheduler.{cc,h}  # Priority FIFO scheduler
│   ├── quic-congestion-ops.{cc,h}      # Congestion control base
│   └── quic-bbr.{cc,h}                # BBR congestion control
├── helper/
│   └── quic-helper.{cc,h}             # Simulation setup helper
├── examples/
│   └── quic-example.cc                # Basic usage example
└── test/                              # Unit tests
```

---

## Building

This module requires ns-3 with CMake support. From the ns-3 root:

```bash
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

## Running the Example

```bash
./ns3 run quic-example
```

---

## Known Limitations

- **No connection migration** (RFC 9000 §9) — reconnection is used instead.
- **No TLS/QUIC integration** (RFC 9001) — the security layer is not simulated.
- Loopback support requires special handling due to ns-3's UDP socket internals.

---

## Original Authors

[SIGNET Lab](https://github.com/signetlabdei), Department of Information Engineering, University of Padova:

- Alvise De Biasio
- Federico Chiariotti
- Michele Polese
- Davide Marcato
- Umberto Paro

## Fork Maintainer

RFC 9000 / RFC 9002 updates and ns-3 integration patches:

- Fernando Areias — nando.calheirosx@gmail.com

## License

GNU General Public License v2.0 — see individual source files for full license headers.