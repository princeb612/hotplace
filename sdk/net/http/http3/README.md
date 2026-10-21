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
# HTTP/3 frames

## 1. Role

`sdk/net/http/http3` contains HTTP/3 frame representations and builders. It is the HTTP message/frame layer above QUIC streams. QUIC packet processing, stream transport, and TLS 1.3 handshake/key integration live under `sdk/net/tls/quic` and the related TLS session code.

The presence of HTTP/3 frame classes is not evidence that the full HTTP/3 server path is implemented; the current server integration remains incomplete.

## 2. Data Model

The source defines the `http3_frame` abstraction, a builder, and concrete frame types including DATA, HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID, PRIORITY_UPDATE, ORIGIN, METADATA, and unknown-frame handling.

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

## 4. Relationships

- `http3_frame.hpp/.cpp`, `http3_frame_builder.hpp/.cpp`, `http3_frame_*.hpp/.cpp` — HTTP/3 frame model.
- [QPACK](../qpack/README.md) and [compression infrastructure](../compression/README.md) — field-section compression and table state.
- [QUIC transport](../../tls/quic/README.md) — packets, frames, streams, and connection/session behavior.
- [TLS/DTLS/QUIC overview](../../tls/README.md) — TLS 1.3 handshake and protection boundary.
- [Trial socket composer](../../basic/trial-socket-composer.md) and [trial implementations](../../basic/trial/README.md) — current QUIC/TLS handshake composition path.
- [HTTP core model](../http-core-model.md) — common request/response semantics.
- [HTTP server/client flow](../http-server-client.md) — server configuration and the incomplete HTTP/3 service path.
- `test/testcase/net/qpack/` — QPACK vectors; these are not a substitute for direct HTTP/3 frame/server tests.

## 5. References

- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9204 — QPACK: Field Compression for HTTP/3](https://www.rfc-editor.org/rfc/rfc9204)
- [HTTP/3 parameters](https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml)
- [HTTP fields](https://www.iana.org/assignments/http-fields/http-fields.xhtml)
