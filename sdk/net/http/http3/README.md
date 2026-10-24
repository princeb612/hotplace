## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HTTP/3 frames

## 1. Role

`sdk/net/http/http3` contains HTTP/3 frame representations and builders. It is the HTTP message/frame layer above QUIC streams. QUIC packet processing, stream transport, and TLS 1.3 handshake/key integration live under `sdk/net/tls/quic` and the related TLS session code.

The presence of HTTP/3 frame classes is not evidence that the full HTTP/3 server path is implemented. In the current source, `http_server::startup_server()` registers the HTTP/1.x protocol and optionally the HTTP/2 protocol, but no HTTP/3 `network_protocol`; `http_response::respond()` also has no HTTP/3 response branch. The current server integration therefore remains incomplete.

## 2. Data Model

The source defines the `http3_frame` abstraction, a builder, and concrete frame types including DATA, HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID, PRIORITY_UPDATE, ORIGIN, METADATA, and unknown-frame handling.

The representation boundary consists of three associated layers:

- **QUIC transport model:** packet protection, connection state, and stream byte ranges; TLS 1.3 handshake bytes use QUIC CRYPTO frames.
- **HTTP/3 frame model:** DATA, HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID, PRIORITY_UPDATE, ORIGIN, METADATA, and unknown-frame representations.
- **QPACK field-section model:** HEADERS carries a QPACK field section; QPACK owns its indexed/literal field representation and compression state.

HTTP/3 does not use the TLS record layer to carry application frames. QUIC integrates TLS 1.3 handshake messages and derives transport protection keys, while HTTP/3 frames are carried on QUIC streams after the QUIC connection is established. This is different from HTTPS over TCP, where TLS records wrap the application byte stream.

## 3. Behavior Model

### TLS and QUIC boundary

The TLS 1.3 handshake is required for QUIC connection establishment and key derivation, but the handshake bytes travel in QUIC CRYPTO frames rather than ordinary TLS records. In this repository, the experimental composer path under `sdk/net/basic/trial` constructs QUIC/TLS handshake material, while `sdk/net/tls/quic/` owns QUIC packet/frame and session machinery. HTTP/3 consumes the resulting QUIC stream data; it does not perform the TLS handshake itself.

```text
trial TLS composer / TLS session
  -> TLS 1.3 handshake messages
  -> QUIC CRYPTO frames
  -> QUIC packet protection and transport
  -> QUIC streams
  -> HTTP/3 frames
  -> QPACK decode for HEADERS
  -> HTTP request semantics
```

This diagram shows the architectural dependency, not a claim that the current source has a complete end-to-end HTTP/3 server.

### Frame behavior

HTTP/3 framing is stream-based within QUIC. DATA carries body bytes; HEADERS carries a QPACK-encoded field section; control and extension frames have their own stream and protocol constraints. QUIC packet boundaries are not HTTP message boundaries, and a single HTTP/3 frame is not necessarily a complete request. QPACK owns header field compression, while this directory owns the HTTP/3 frame model.

```text
QUIC connection
  ├─ QUIC packets / protection / streams
  │    └─ TLS 1.3 handshake-derived key material
  │         (TLS handshake messages carried as QUIC CRYPTO data)
  └─ QUIC stream bytes
       ▼
    HTTP/3 frame parser / frame objects
       ├─ DATA -> body bytes
       ├─ HEADERS -> QPACK field section
       └─ SETTINGS / GOAWAY / push / priority / extension frames
```

This view separates QUIC transport and protection from HTTP/3 frame interpretation. The TLS-derived key material belongs to QUIC's transport-protection setup; the HTTP/3 parser consumes stream bytes, not QUIC packet boundaries. The frame-to-semantics flow below expands what happens after stream bytes reach the HTTP/3 framing layer.

### Frame-to-semantics flow

```text
QUIC stream reassembly
  -> identify HTTP/3 frame type and variable-length frame length
  -> wait until the frame payload is available
  -> DATA: body contribution
  -> HEADERS: QPACK field section
  -> decode field section using QPACK table/instruction state
  -> assemble HTTP message state across frames/streams
  -> common HTTP request/response semantics
```

This is the conceptual layering boundary only. The source has frame types and QPACK support, but does not yet provide the complete end-to-end HTTP/3 server/session dispatch path. Do not present the diagram as a verified runtime execution path.

## 5. Relationships
- `http3_frame.hpp/.cpp`, `http3_frame_builder.hpp/.cpp`, `http3_frame_*.hpp/.cpp` — HTTP/3 frame model.
- [QPACK](../qpack/README.md) and [compression infrastructure](../compression/README.md) — field-section compression and table state.
- [QUIC transport](../../tls/quic/README.md) — packets, frames, streams, and connection/session behavior.
- [TLS/DTLS/QUIC overview](../../tls/README.md) — TLS 1.3 handshake and protection boundary.
- [Trial socket composer](../../basic/trial/trial-socket-composer.md) and [trial implementations](../../basic/trial/README.md) — current QUIC/TLS handshake composition path.
- [HTTP core model](../http-core-model.md) — common request/response semantics.
- [HTTP server/client flow](../http-server-client.md) — server configuration and the incomplete HTTP/3 service path.
- `test/testcase/net/qpack/` — QPACK vectors; these are not a substitute for direct HTTP/3 frame/server tests.

## 6. References
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9204 — QPACK: Field Compression for HTTP/3](https://www.rfc-editor.org/rfc/rfc9204)
- [HTTP/3 parameters](https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml)
- [HTTP fields](https://www.iana.org/assignments/http-fields/http-fields.xhtml)
