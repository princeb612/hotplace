# Network server

`server` is the network-server orchestration layer above the socket implementations in `sdk/net/basic/`.

Its main responsibility is to connect the platform multiplexer, socket accept/read events, sessions, and protocol processing into a threaded server flow.

## Module records

- [server mindmap](server-mindmap.md) — original component relationship map
- [server notes](server-notes.md) — original `network_server` platform support and thread/event flow
- [network server model](network-server-model.md) — implementation-oriented server lifecycle and event flow
- [network session](network_session.md) — session ownership and protocol boundary
- [network stream and protocol](network-stream-and-protocol.md) — stream/protocol processing boundary

## Related tests

- [network testcase](../../test/testcase/net/README.md)
- `test/testcase/net/sample.cpp`

## Related areas

- `sdk/net/basic/` — socket implementations
- `sdk/net/tls/` — TLS/DTLS/QUIC secure transport
- `sdk/net/http/` — HTTP server/protocol layer
