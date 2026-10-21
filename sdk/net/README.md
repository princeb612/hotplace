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

## 2. Data Model

### Directory map

The main components can be read as this text-based relationship map:

```text
Application / protocol consumer
  ├─ may use server/
  │    └─ uses basic/ for socket and backend operations
  ├─ may use basic/ directly
  └─ may use http/ for HTTP protocol processing
       ├─ uses io/ for representations and parsing
       └─ uses tls/ when the selected HTTP version/transport requires it

basic/ ── may integrate with ──> tls/
tls/   ── uses ──> sdk/crypto/ for cryptographic operations
tls/   ── uses ──> sdk/io/     for payloads, parsing and streams
server/ and basic/ ── use ──> sdk/base/ common types and utilities
```

This is a conceptual relationship map, not a complete include graph or a mandatory call sequence. A plain TCP client, for example, does not need to traverse the TLS or HTTP layers.

### Responsibilities by subdirectory

| Area | Main responsibility | Questions to answer in its component documents |
|---|---|---|
| `basic/` | Socket lifecycle, transport backends, address access control | Who owns the native socket? How are connect/accept/read/write and close represented? |
| `server/` | Multiplexer/event handling and session orchestration | How does an accepted socket become a session, and how is protocol work scheduled? |
| `tls/` | TLS/DTLS records and handshakes; QUIC packet/frame-related processing | Which state belongs to the secure session, record, or packet? How are transport differences handled? |
| `http/` | HTTP protocol processing and version-specific framing/compression | Which HTTP version and framing rules does a given implementation path handle? |

## 3. Behavior Model

### Socket, session, and protocol are separate concerns

A socket represents a transport endpoint and its platform resources. A server session represents a higher-level unit of connection or protocol state. TLS/DTLS/QUIC processing adds security and transport-specific state, while HTTP adds application-protocol semantics. These concepts interact, but should not be documented as if they were one object with one lifetime.

When tracing an implementation, establish these points from the source:

1. **Resource creation:** which object opens, accepts, or wraps the native socket.
2. **State ownership:** where connection/session state and protocol state are stored.
3. **Event handoff:** how readable/writable/timeout events reach the relevant session or protocol handler.
4. **Data boundary:** whether bytes are raw transport data, TLS records, DTLS records, QUIC packets/frames, or HTTP messages.
5. **Shutdown:** which component closes native resources and which component releases protocol/session state.

Do not infer a universal lifecycle from class names alone; confirm the concrete path in the relevant implementation and tests.

### TLS, DTLS, and QUIC need a shared view without erasing their differences

The secure transport area contains useful material for studying the common session/record abstraction, but the wire-level units are not identical:

- TLS commonly processes an ordered byte stream containing TLS records.
- DTLS uses datagram-oriented records and has transport-specific sequencing/arrangement concerns.
- QUIC uses packets and frames over UDP, with TLS handshake messages carried through QUIC's crypto machinery rather than ordinary TLS records on a TCP stream.

The source components `dtls_record_arrange`, `dtls_record_publisher`, and `quic_packet_publisher` should therefore be read as evidence of how hotplace represents and publishes transport-specific units around session-level processing. Their relationship belongs in the TLS component documentation; this directory overview only identifies the boundary.

### Build and capability boundary

A directory's presence does not guarantee that every backend, protocol version, extension, or optional feature is enabled in every build. Use the relevant CMake configuration and source guards when stating platform or feature support. Keep implementation claims separate from protocol-standard requirements.

## 4. Relationships

- `sdk/base/` — shared data types, strings, in-memory streams, algorithms, and platform-adjacent helpers.
- `sdk/io/` — payload field layouts, parsing infrastructure, CBOR/ASN.1 and other representation facilities.
- `sdk/crypto/` — cryptographic primitives, keys, algorithm metadata, and format-specific cryptography.

The relationship map above is conceptual. Individual include dependencies and actual call direction should be confirmed in the component source.

### Component navigation

- [Socket layer](basic/README.md)
- [Server layer](server/README.md)
- [TLS/DTLS/QUIC area](tls/README.md)
- [HTTP area](http/README.md)

## 5. References

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

## 6. Developer Notes

- Preserve the original protocol/reference material when reorganizing the document; move it under References rather than deleting it.
- Keep detailed TLS/DTLS/QUIC state and record/packet relationships in `tls/` component documents. This README should provide orientation and boundaries, not duplicate the implementation walkthrough.
- Keep HTTP/2 HPACK and HTTP/3 QPACK distinct. Shared purpose does not mean identical wire format or algorithm.
- When a future update adds variable-length payload handling or changes record/packet publication, cross-check `sdk/io/basic/payload`, `sdk/net/tls`, and the relevant testcase sources together.
