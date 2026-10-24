## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ Documentation scope: directory identity and  │
│ implementation navigation                    │
└──────────────────────────────────────────────┘
```

# Network SDK

## 1. Role

`sdk/net` contains the network-facing abstractions and protocol implementations in hotplace. It spans socket backends, server/session orchestration, secure transport, and HTTP-family protocols. It is not a single networking stack in which every connection must pass through every subdirectory: the concrete path depends on the transport and protocol selected by the application.

The principal boundaries are:

- `basic/` — socket abstractions and concrete transport/backend adapters.
- `server/` — server-side coordination of sockets, multiplexing, sessions, and protocol processing.
- `tls/` — TLS, DTLS, and QUIC-related transport and record/packet processing.
- `http/` — HTTP protocol layers, including HTTP/1.x, HTTP/2, and HTTP/3-related facilities.

This directory is responsible for network and protocol behavior. Cryptographic operations and key abstractions are supplied by `sdk/crypto`; common representations, parsing, and I/O facilities are supplied by `sdk/base` and `sdk/io`.

### Start from the task you want to try

| If you want to… | Start here | What the example helps you understand |
|---|---|---|
| Run a plain TCP echo server | [`tcpserver2`](../../test/applet/tcpserver2/README.md), then [server model](server/README.md) | How a listener, event loop, session callback, and echo response fit together. |
| Try TCP, UDP, TLS, or DTLS against a server | [`netclient`](../../test/applet/netclient/README.md) | How the selected transport changes connect/read behavior; TCP/TLS may need multiple reads, while UDP/DTLS preserve datagram semantics. |
| Compare OpenSSL and trial secure-socket paths | [`tlsserver`](../../test/applet/tlsserver/README.md), then [socket layer](basic/README.md) | How scheme/backend selection is separate from server orchestration and handshake processing. |
| Apply a peer-address allow/deny policy | [IP address and ACL](basic/ipaddr/README.md), with the [TCP server example](../../test/applet/tcpserver2/README.md) | How whitelist/blacklist rules produce a decision and the caller enforces it through accept control. |
| Handle an HTTP/1.1 request and route it | [HTTP layer](http/README.md), then [`httpserver1`](../../test/applet/httpserver1/README.md) | Where a completed request becomes an application response, and that routing is explicitly invoked by the callback. |
| Try HTTP/2 with the shared server abstraction | [`httpserver2`](../../test/applet/httpserver2/README.md), then [HTTP layer](http/README.md) | How HTTP/2 changes protocol/session handling without replacing the shared server orchestration. |
| Understand TLS vs DTLS vs QUIC wire units | [TLS/DTLS/QUIC](tls/README.md) | Why TLS records, DTLS datagram records, and QUIC packets/frames must not be treated as the same framing path. |

These applets are practical integration entry points, not a claim that every backend or protocol combination has been tested on every platform. In particular, the presence of HTTP/3 and QUIC-related classes should not be read as proof of a complete HTTP/3 server path.

## 2. Data Model

### Cross-layer entities and ownership boundaries

```text
Native transport resource
  └─ socket object (sdk/net/basic)
       ├─ endpoint / scheme / backend state
       └─ used by server orchestration when applicable

Server coordination state (sdk/net/server)
  ├─ multiplexer and worker configuration
  ├─ session manager
  └─ per-session state
       ├─ peer / transport metadata
       ├─ raw transport input
       ├─ protocol-composed messages
       └─ application/session key-value data

Secure transport state (sdk/net/tls)
  ├─ handshake messages and extensions
  ├─ negotiated session/protection state
  └─ transport-specific wire state
       ├─ TLS records
       ├─ DTLS epoch + record sequence
       └─ QUIC packet-number spaces and frames

HTTP semantic state (sdk/net/http)
  ├─ request / response
  ├─ URI / header / body
  └─ version-specific framing and compression state
```

These entities have different ownership and lifetimes. A socket is a platform transport resource; a network session retains per-connection or per-peer processing state; TLS protection retains negotiated and directional cryptographic state; HTTP request/response objects represent semantic messages rather than raw socket buffers. UDP/DTLS peer state and QUIC connection state must not be reduced to the TCP accepted-socket model.

The model is intentionally conceptual: each component document identifies the concrete fields, ownership rules, and lifetime details for its own types.

## 3. Behavior Model

### TCP server path

```text
server configuration
  -> server_socket_adapter selects backend-qualified scheme
  -> server_socket_builder creates/configures concrete listener
  -> network_server opens listener and event workers
  -> accept event
  -> accepted socket
  -> network_session registration + multiplexer binding
  -> producer/consumer processing
  -> protocol framing
  -> application/protocol handler
```

For a secure stream listener, TCP accept and TLS handshake are separate stages: the accepted socket may pass through the TLS-accept queue/worker before normal session processing. The server layer coordinates these stages; the concrete socket backend performs the transport operation, and the protocol layer interprets completed messages.

### Transport and protocol paths diverge at the wire boundary

```text
TCP  -> ordered bytes -> [optional TLS records] -> protocol messages
UDP  -> datagrams     -> [optional DTLS records] -> peer/session processing
UDP  -> QUIC packets -> frames -> CRYPTO bytes / STREAM payload
                                      |                 |
                                      v                 v
                                 TLS handshake      application data
```

HTTP processing follows the protocol selected by the application and available implementation path: HTTP/1.x frames byte messages, HTTP/2 assembles frames and stream state, and HTTP/3 consumes HTTP frames over QUIC streams. These paths can converge on shared HTTP request/response semantics, but do not share one wire format.

### Lifecycle boundary

Creation, event delivery, protocol processing, and shutdown are coordinated across separate objects. When following a concrete call path, distinguish (1) opening/accepting the native socket, (2) registering and scheduling a session, (3) transforming transport bytes into protocol units, and (4) closing the transport resource versus releasing session/protocol state. The exact order and cleanup owner are backend- and path-dependent; use the component documents rather than assuming one universal lifecycle.

### TLS, DTLS, and QUIC need a shared view without erasing their differences

The secure transport area contains useful material for studying the common session/record abstraction, but the wire-level units are not identical:

- TLS commonly processes an ordered byte stream containing TLS records.
- DTLS uses datagram-oriented records and has transport-specific sequencing/arrangement concerns.
- QUIC uses packets and frames over UDP, with TLS handshake messages carried through QUIC's crypto machinery rather than ordinary TLS records on a TCP stream.

The source components `dtls_record_arrange`, `dtls_record_publisher`, and `quic_packet_publisher` should therefore be read as evidence of how hotplace represents and publishes transport-specific units around session-level processing. Their relationship belongs in the TLS component documentation; this directory overview only identifies the boundary.

### Build and capability boundary

A directory's presence does not guarantee that every backend, protocol version, extension, or optional feature is enabled in every build. Use the relevant CMake configuration and source guards when stating platform or feature support. Keep implementation claims separate from protocol-standard requirements.

### Real-code entry points

The directory-level diagrams are easiest to ground in three runnable callers:

- `test/applet/tcpserver2/run_server.cpp` — opens listeners with `network_server`, registers accept control, and echoes data from a consumer callback. Use it to follow the plain TCP server lifecycle.
- `test/applet/tlsserver/run_server.cpp` — selects OpenSSL or trial socket schemes and TLS version flags before entering the same network-server orchestration. Use it to distinguish application callbacks from handshake/record processing.
- `test/applet/httpserver2/run_server.cpp` — builds an HTTP server, enables HTTP/2, and dispatches completed requests through `http_router` before responding. Use it to follow the boundary between transport/session processing and application semantics.

These examples are intentionally complementary rather than one universal path. A callback receiving application data does not itself demonstrate how bytes were framed, how a handshake was negotiated, or how a request became complete; follow the corresponding component Behavior Model for those steps.
## 5. Relationships
```text
Application / protocol consumer
  ├─ server/ ── coordinates ──> basic/ socket backends
  │      └─ manages sessions / events / protocol hand-off
  ├─ may use basic/ directly
  └─ http/ ── uses ──> server/session integration as configured
          ├─ sdk/io/ for representation and parsing
          └─ tls/ or QUIC path when required by selected protocol

basic/ ── secure backends may integrate with ──> tls/
tls/   ── cryptographic operations ──> sdk/crypto/
tls/   ── payloads, parsing and streams ──> sdk/io/
server/ and basic/ ── common types/utilities ──> sdk/base/
```

This is a conceptual dependency map, not a complete include graph or mandatory call sequence. A plain TCP client need not traverse TLS or HTTP; HTTP/3 uses QUIC streams rather than the TLS record path.

- `sdk/base/` — shared data types, strings, in-memory streams, algorithms, and platform-adjacent helpers.
- `sdk/io/` — payload field layouts, parsing infrastructure, CBOR/ASN.1 and other representation facilities.
- `sdk/crypto/` — cryptographic primitives, keys, algorithm metadata, and format-specific cryptography.

The relationship map above is conceptual. Individual include dependencies and actual call direction should be confirmed in the component source.

### Component navigation

- [Socket layer](basic/README.md)
- [Server layer](server/README.md)
- [TLS/DTLS/QUIC area](tls/README.md)
- [HTTP area](http/README.md)

## 6. References
### Protocol specifications

- TLS 1.0: [RFC 2246](https://www.rfc-editor.org/rfc/rfc2246)
- TLS 1.1: [RFC 4346](https://www.rfc-editor.org/rfc/rfc4346)
- TLS 1.2: [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)
- TLS 1.3: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
- TLS 1.3 example traces: [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448)
- DTLS 1.2: [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)
- DTLS 1.3: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)
- QUIC: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- Using TLS to secure QUIC: [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)
- HTTP/2: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
- HPACK: [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
- HTTP/3: [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)
- QPACK: [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)

### Online study and diagnostic resources

- [TLS 1.3 Illustrated](https://tls13.xargs.org/)
- [TLS 1.2 Illustrated](https://tls12.xargs.org/)
- [DTLS Illustrated](https://dtls.xargs.org/)
- [QUIC Illustrated](https://quic.xargs.org/)
- [IANA TLS parameters](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)
- [IANA QUIC registry](https://www.iana.org/assignments/quic/quic.xhtml)
- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)

## Developer Notes
- Preserve the original protocol/reference material when reorganizing the document; move it under References rather than deleting it.
- Keep detailed TLS/DTLS/QUIC state and record/packet relationships in `tls/` component documents. This README should provide orientation and boundaries, not duplicate the implementation walkthrough.
- Keep HTTP/2 HPACK and HTTP/3 QPACK distinct. Shared purpose does not mean identical wire format or algorithm.
- When a future update adds variable-length payload handling or changes record/packet publication, cross-check `sdk/io/basic/payload`, `sdk/net/tls`, and the relevant testcase sources together.
