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

- TCP uses a stream socket. The server opens a listener and accepts a connected socket; client/server reads and writes operate on the byte stream.
- UDP uses datagrams. There is no TCP-style accepted stream connection; send/receive operations may carry a peer address, and message boundaries remain significant.

These classes are the transport implementation, not the server's session manager or application protocol.

## 3. Behavior Model

### Server path

```text
network_server
  │ configure/open listener through server_socket
  ▼
naive_tcp_server_socket
  │ listen socket registered with multiplexer
  ▼
TCP accept event
  │ accept() -> connected client socket + peer address
  ▼
network_server accept/session flow
  │ associate socket with session / stream processing
  ▼
network_stream -> protocol consumer
```

This is the architectural hand-off: `naive_tcp_server_socket` performs the native listener/accept/read/write operations, while `network_server` coordinates event registration, accepted-socket lifecycle, sessions, buffering, and protocol dispatch. The naive class does not itself decide which HTTP or other application protocol consumes the bytes.

For UDP, do not project the TCP accept flow onto the datagram path. UDP uses socket readiness and datagram receive/send operations rather than creating one accepted stream socket per peer. Higher-level session behavior depends on the caller and selected server implementation.

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
