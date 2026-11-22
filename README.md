# QUIC Module for ns-3

An ns-3 contrib module implementing the **QUIC transport protocol**, forked from [signetlabdei/quic](https://github.com/signetlabdei/quic) and updated to improve RFC compliance.

---

## Overview

This module provides a simulation-ready QUIC stack for ns-3.

### RFC Compliance

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | Behaviour follows the RFC (streams, flow control, connection ids, migration, closing, stateless reset, frame layouts). The packet *header* layout is only partly the RFC's, see [Wire format](#wire-format) |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | Followed: RTT estimation, packet and time thresholds, PTO, NewReno, persistent congestion. Two msquic choices are the defaults and can be switched, see [Deliberate deviations](#deliberate-deviations-from-the-rfcs) |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | Not implemented — there is no TLS, no packet protection, no key update |
| [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438) | CUBIC | Default congestion control (HyStart++, RFC 9406, optional and off) |

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
│   ├── quic-congestion-ops.{cc,h}      # Congestion control base (NewReno)
│   ├── quic-cubic.{cc,h}               # CUBIC + pacing (default, as msquic; HyStart++ optional, off like msquic)
│   ├── quic-stream-id-tag.{cc,h}       # Byte tag identifying the stream of delivered data
│   └── quic-bbr.{cc,h}                # BBR congestion control
├── helper/
│   └── quic-helper.{cc,h}             # Simulation setup helper
├── examples/
│   └── quic-example.cc                # Basic usage example
└── test/                              # Frame/recovery unit tests + end-to-end tests (loss, flow control, close, reset, blackout, reordering)
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

## Wire format

The frame layouts are the ones of RFC 9000 §19: variable-length integers, ACK ranges as counts relative to the
previous range, error codes as integers, the frame type in the transport CONNECTION_CLOSE, the length byte of
NEW_CONNECTION_ID, and a first byte per §17 (Fixed Bit, spin bit, key phase and packet number length). Version
Negotiation is the long header whose version is 0, with the versions in network byte order. What is still not the
RFC's, because the module has no TLS and no packet protection:

- Long headers carry no Source Connection ID, no Token and no Length field, and the packet number is always 4 bytes;
  packet numbers are 32 bits (the RFC allows 62).
- Connection ids are always 8 bytes. `OmitConnectionId` (short headers without the id) is flagged in a reserved bit,
  which the RFC does not have: a header that carries the id is a valid RFC 9000 short header.
- The transport parameters are a fixed 72-byte structure, not the TLV list of RFC 9000 §18, and travel in the
  handshake payload instead of a TLS extension. The idle timeout there is in milliseconds, as in the RFC.
- No Retry, no address-validation tokens (`NEW_TOKEN` is ignored by clients and a protocol violation for servers),
  no CRYPTO frames, no coalesced packets, no ECN marking (only the ACK_ECN counts are read).

## Deliberate deviations from the RFCs

- **Persistent congestion** is detected as msquic does it (a loss after more than 2 consecutive PTOs). The RFC 9002
  §7.6 duration test is there: `PersistentCongestionByPto=false`.
- **ACK_FREQUENCY** and **IMMEDIATE_ACK** are the ack-frequency draft's, as in msquic; the ACK_FREQUENCY type is
  written in one octet where the draft uses a two-byte integer.
- **min_ack_delay** and the ACK tolerance of up to 41 packets go beyond RFC 9000 §13.2.2 (an ACK at least every second
  packet), through that draft.
- The draining state after a CONNECTION_CLOSE from the peer lasts three PTOs (RFC 9000 §10.2.2); the closing state of
  the endpoint that closes is the `DrainingPeriodTimeout` attribute.

## Known Limitations

- **Migration is client-initiated only** (RFC 9000 §9) — no `preferred_address` and no multipath.
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
## Alinhamento com o msquic

Comportamentos de produção reproduzidos (conferidos contra o fonte do msquic):

- **Congestionamento:** CUBIC (RFC 9438) com fast convergence e desfazimento de reduções por perda espúria;
  HyStart++ opcional e desligado (padrão do msquic); pacing por permissão de envio (2x o `cwnd` em slow start,
  1,25x depois, blocos de 1 ms, só com amostra de RTT e `srtt` >= 1 ms); congestionamento persistente quando uma
  perda é detectada após mais de 2 PTOs seguidos (`cwnd` = 2 pacotes, `ssthresh` = 0,7 do `cwnd`).
- **Perdas e PTO:** perda por pacote quando `pn + 3 <= maior ACK` (RFC 9002 §6.1.1; o msquic espera um pacote a
  mais, o que se obtém com `kReorderingThreshold=4`) e por tempo (9/8 do RTT); PTO medido a partir do último envio
  que pede confirmação, com 2 pacotes de sonda isentos da janela (dados novos, depois os mais antigos, depois um
  PING); fechamento por falta de progresso (`DisconnectTimeout`, 16 s) e por inatividade (30 s, notificado como
  erro de transporte; 0 desliga o temporizador e o valor negociado é o menor dos dois, nunca menos de 3 PTOs).
- **ACK:** a cada 2 pacotes que pedem confirmação, em até 25 ms, e imediato quando um pacote novo deixa uma lacuna
  ainda não reportada. O atraso do ACK é contado do maior pacote recebido, em microssegundos divididos por
  2^`AckDelayExponent` (3), e é subtraído da amostra de RTT só depois do handshake, até `max_ack_delay` e sem
  passar do RTT mínimo (RFC 9002 §5.3).
- **Controle de fluxo:** janela inicial de 64 KiB por stream, atualizada quando 1/4 foi consumido e dobrada se a
  atualização ocorre em cerca de 1 RTT (até a janela da conexão); janela da conexão de 16 MiB deslizante
  (`MaxData` cresce a cada byte entregue, MAX_DATA a cada 1/4); DATA_BLOCKED/STREAM_DATA_BLOCKED; FLOW_CONTROL_ERROR.
- **Streams:** escalonamento FIFO por stream (padrão do msquic; o stream mantém o lugar enquanto tiver dados,
  inclusive no próprio buffer), prioridade de stream (`SetStreamPriority`, padrão 0x7FFF), RESET_STREAM e
  STOP_SENDING (`ResetStream`, `StopSending`, trace `StreamReset`). FIFO por quadro continua como opção
  (`SchedulingPolicy`). Há também o round-robin do msquic (`QuicSocketTxRoundRobinScheduler`): cada stream envia
  lotes de 8 pacotes e passa ao fim da fila; um stream ocioso não acumula crédito.
- **Caminho:** descoberta do MTU (DPLPMTUD): começa em 1288 bytes e sobe de 80 em 80 até 1500; três sondas sem
  resposta encerram a busca (`EnableMtuDiscovery`).
- **Handshake e fechamento:** handshake em 1 RTT com retransmissão; `Close()` descarrega os dados pendentes; o
  HANDSHAKE_DONE e o MAX_DATA de resposta a DATA_BLOCKED seguem pelo buffer de transmissão e são reenviados se o
  pacote se perde; quem recebe um CONNECTION_CLOSE avisa o aplicativo na hora e mantém o estado por 3 PTOs;
  `DisableActiveMigration` anuncia `disable_active_migration` e `Migrate()` recusa se o par o anunciou.

- **Streams:** identificadores e tipos conforme a RFC 9000 (o bit menos significativo indica o iniciador e o
  seguinte a direção: cliente 0, 4, 8; servidor 1, 5, 9; unidirecionais 2 e 3); abrir um id abre os anteriores do
  mesmo tipo; limites de streams do par (`MaxStreamIdBidi`/`MaxStreamIdUni`, padrão 0 como o `PeerBidiStreamCount`
  do msquic) com STREAMS_BLOCKED e MAX_STREAMS; um stream do par que termina nos dois sentidos devolve crédito
  (um MAX_STREAMS); `FinishStream()` encerra o envio com FIN. Escritas feitas durante o handshake esperam a
  conexão abrir, como no msquic. Limite de dados por stream conforme o tipo (`initial_max_stream_data_*`).
- **ACK frequency:** o módulo anuncia `min_ack_delay`, aceita ACK_FREQUENCY e IMMEDIATE_ACK e, como o msquic, pede ao
  par tolerância maior quando o envio é limitado pelo escalonamento (mais de 40 datagramas por rodada) e a volta a
  2 depois de congestionamento persistente.
- **Stateless reset:** o servidor responde a um pacote curto sem conexão com um reset de 41 a 48 bytes cujo final é
  o token derivado (chave secreta + id da conexão); o cliente que reconhece o token anunciado nos parâmetros fecha
  a conexão sem esperar o `DisconnectTimeout`.

- **Ids de conexão e migração:** cada ponta emite ids de conexão (NEW_CONNECTION_ID, com token de stateless reset)
  até o limite do par (`active_connection_id_limit` 4, como o msquic) e reemite quando o par aposenta um
  (RETIRE_CONNECTION_ID); o L4 roteia por qualquer id emitido. Um pacote que chega de um endereço novo cria um
  caminho; o primeiro pacote válido dispara PATH_CHALLENGE no caminho novo e no ativo; frames que não são de
  sondagem em pacote novo ativam o caminho, que recomeça do MTU mínimo, do RTT inicial e do congestionamento
  inicial (só uma troca de porta preserva o congestionamento). Caminho não validado envia no máximo 3 vezes o que
  recebeu; a validação expira em 3 PTOs (no mínimo 6 RTTs iniciais) e o caminho é removido. O MTU é por
  caminho. O cliente migra com `Migrate(endereço)`, que troca o socket UDP e manda um PING, como
  `QUIC_PARAM_CONN_LOCAL_ADDRESS`. Depois de 20 s sem enviar (`DestCidUpdateIdleTimeout`) o id de destino
  muda e o par responde mudando o seu.

Simplificações e itens ausentes:

- TLS (RFC 9001). Migração só por mudança de endereço local do cliente: sem `preferred_address` nem multipath.
- Keep-alive não é implementado: o msquic o traz desligado por padrão.
- O tipo de frame ACK_FREQUENCY usa um octeto no lugar do inteiro de tamanho variável da especificação.
- Os `connection id` dos parâmetros de transporte (`initial_source_connection_id`,
  `original_destination_connection_id`, RFC 9000 §7.3) não são conferidos: o módulo usa um só id por conexão e não
  tem Retry, então um desencontro só viria de um par defeituoso.
- O crédito de streams é devolvido quando o stream do par termina nos dois sentidos; o msquic espera o aplicativo
  fechar o stream.
- O desafio de caminho vai num pacote próprio e é repetido por temporizador; o msquic o retransmite como qualquer
  frame que pede confirmação.

## Reproducing the streaming scenarios

`resultados/sweep-cenarios.py` runs the full sweep (uniform, burst, jitter, path change and the congestion-control comparison) into `resultados/cenarios.csv`. With `ONLY=<cenario>` (`uniforme`, `rajada`, `jitter`, `caminho`, `cc`) it reruns one scenario and replaces only its rows in the same file. The `cc` scenario compares QUIC congestion controls (BBR, NewReno) under uniform loss.
