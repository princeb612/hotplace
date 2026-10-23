## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Naive TCP/UDP socket wrappers

## 1. Role

This directory contains direct TCP/UDP client and server socket implementations behind the common `client_socket` and `server_socket` contracts. “Naive” means that these classes provide the transport socket operations without adding TLS/DTLS state or the trial prosumer/composer machinery.

## 2. Data Model

```text
client_socket                    server_socket
  ├─ naive_tcp_client_socket       ├─ naive_tcp_server_socket
  └─ naive_udp_client_socket       └─ naive_udp_server_socket
```

The model distinguishes stream endpoints from datagram endpoints. TCP's ordered byte stream and UDP's message boundaries are transport semantics; neither is an application-protocol session model.

## 3. Behavior Model

### 3.1 TCP server accept and session hand-off

```text
network_server configures listener
             |
             v
naive_tcp_server_socket
             |
         listen()
             |
             v
multiplexer reports accept readiness
             |
             v
accept() -> connected socket + peer address
             |
             v
network_server attaches socket to session/stream
             |
             v
network_stream -> protocol consumer
```

`naive_tcp_server_socket` performs native listener/accept/read/write operations. `network_server` coordinates event registration, accepted-socket lifecycle, sessions, buffering and protocol dispatch. The socket wrapper does not decide which HTTP or other application protocol consumes the bytes.

### 3.2 UDP datagram path

UDP has no TCP-style accept step and does not create one connected stream socket per peer. The server reacts to socket readiness, receives a datagram with its peer-address context, and sends datagrams according to the selected API. Any peer/session association is a higher-level caller/server decision; do not infer a TCP session lifecycle from the UDP wrapper.

## 4. Relationships
- `naive_tcp_client_socket.hpp/.cpp`, `naive_tcp_server_socket.hpp/.cpp`
- `naive_udp_client_socket.hpp/.cpp`, `naive_udp_server_socket.hpp/.cpp`
- [Common socket model](../socket-model.md) — common client/server contract.
- [Basic socket overview](../README.md) — backend families and scheme distinctions.
- [Network server](../../server/README.md) — accept/event/session orchestration above the socket implementation.
- [Trial socket composer](../trial-socket-composer.md) — contrast with the experimental prosumer/handshake path.
- `../../../../test/testcase/net/basic/` — basic network socket testcase sources.

## 5. References
No external references are currently listed.
