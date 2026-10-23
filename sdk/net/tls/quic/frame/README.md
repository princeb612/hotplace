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

# QUIC frame implementation

## 1. Role

The frame layer represents individual QUIC transport/control units and their encoding/decoding behavior. Frames are assembled into packets by the packet layer; they do not own packet numbers, packet headers, or packet protection.

## 2. Data Model

The frame family includes ACK, CRYPTO, STREAM/HTTP3_STREAM, PADDING, PING, RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE, NEW_TOKEN, NEW_CONNECTION_ID, and HANDSHAKE_DONE-related frames.

- **CRYPTO** carries TLS handshake bytes with an offset, not TLS records.
- **STREAM** carries stream ID, offset/length information, and stream data.
- **ACK** carries acknowledgement ranges for received QUIC packets.
- **Control frames** update transport state, flow control, connection IDs, or termination.

Concrete frame bodies use binary field-layout logic from the I/O layer where applicable. `hotplace::io::payload` describes and serializes declared fields; QUIC frame classes define which fields and conditional portions belong to each frame type.

## 3. Behavior Model

```text
TLS handshake bytes
  -> CRYPTO frame: offset + byte range
  -> frame serialization
  -> packet frame collection
  -> QUIC packet header / packet number / protection
  -> UDP datagram
```

On input, packet processing authenticates/decrypts the packet and parses frames; CRYPTO data is delivered to TLS handshake processing according to its offset/reassembly rules. STREAM data is delivered to QUIC stream handling. Frame parsing therefore feeds transport/session state, not directly the HTTP router.

## 5. Relationships

- `quic_frame.hpp/.cpp`, `quic_frame_builder.hpp/.cpp`, `quic_frames.hpp/.cpp`.
- `quic_frame_ack.*`, `quic_frame_crypto.*`, `quic_frame_stream.*`, `quic_frame_http3_stream.*`.
- `quic_frame_connection_close.*`, `quic_frame_reset_stream.*`, `quic_frame_stop_sending.*`.
- [QUIC overview](../README.md) and [packet implementation](../packet/README.md).
- [QUIC packet publisher](../../quic_packet_publisher.md) and [TLS session support](../../session/README.md).
- `sdk/io/basic/payload.hpp/.cpp` — reusable binary payload field-layout support.
- `sdk/net/http/http3/` — HTTP/3-specific stream frames and frame consumers.

## 6. References

- [RFC 9000 — QUIC transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
