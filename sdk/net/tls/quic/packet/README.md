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

# QUIC packet implementation

## 1. Role

The packet layer represents QUIC packet variants and their packet-level header/payload encoding. It sits above frame encoding and below session-associated packet publication and protection.

## 2. Data Model

Packet variants include Initial, Handshake, 0-RTT, 1-RTT, Retry, and Version Negotiation. Common packet abstractions, packet collections, and builders compose headers and frame payloads. Packet-number state is associated with QUIC packet-number spaces and session state; it is not a TLS record sequence number or DTLS epoch/sequence pair.

```text
TLS handshake bytes -> CRYPTO frame ─┐
other transport/control frames ──────┼-> packet builder
                                     │     header + packet number
                                     │     frame payload
                                     └-> protection/publication
```

## 3. Behavior Model

The packet builder encodes packet-level structure; the session/publisher supplies the applicable connection state, packet-number space, payload-size constraints, and protection context. Packet bytes are then handed to the transport send path. A frame encoding by itself is not a packet, and the packet publisher is not itself the UDP socket.

The shared `hotplace::io::payload` abstraction describes binary fields where used by the implementation; it does not replace QUIC-specific packet-header rules, packet-number reconstruction, or protection logic.

## 4. Relationships

- `quic_packet.hpp/.cpp`, `quic_packets.hpp/.cpp`, `quic_packet_builder.hpp/.cpp`.
- `quic_packet_initial.*`, `quic_packet_handshake.*`, `quic_packet_0rtt.*`, `quic_packet_1rtt.*`, `quic_packet_retry.*`, `quic_packet_version_negotiation.*`.
- [QUIC overview](../README.md) and [frame implementation](../frame/README.md).
- [QUIC packet publisher](../../quic_packet_publisher.md) and [TLS session support](../../session/README.md).
- `sdk/io/basic/payload.hpp/.cpp` — reusable binary field-layout abstraction where used by packet/frame code.
- `../../protection/` — TLS-derived secrets and QUIC packet protection.

## 5. References

- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
