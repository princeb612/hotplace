## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Network server

## 1. Role

This document identifies the module or protocol area represented by this file.

## 2. Model

`server` is the network-server orchestration layer above the socket implementations in `sdk/net/basic/`.

Its main responsibility is to connect the platform multiplexer, socket accept/read events, sessions, and protocol processing into a threaded server flow.

### Module records

- [server mindmap](server-mindmap.md) — original component relationship map
- [server notes](server-notes.md) — original `network_server` platform support and thread/event flow
- [network server model](network-server-model.md) — implementation-oriented server lifecycle and event flow
- [network session](network_session.md) — session ownership and protocol boundary
- [network stream and protocol](network-stream-and-protocol.md) — stream/protocol processing boundary

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

### Related tests

- [network testcase](../../../test/testcase/net/README.md)
- `test/testcase/net/sample.cpp`

## 5. Relationships

### Related areas

- `sdk/net/basic/` — socket implementations
- `sdk/net/tls/` — TLS/DTLS/QUIC secure transport
- `sdk/net/http/` — HTTP server/protocol layer

## 6. References

Source references and related documents are retained here where available.
