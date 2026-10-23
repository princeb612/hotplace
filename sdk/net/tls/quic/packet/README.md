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

# QUIC packet implementation

## 1. Role

The packet layer represents QUIC packet variants and their packet-level header/payload encoding. It sits above frame encoding and below session-associated packet publication and protection.

## 2. Data Model

Packet variants include Initial, Handshake, 0-RTT, 1-RTT, Retry, and Version Negotiation. Common packet abstractions, packet collections, and builders compose headers and frame payloads. Packet-number state is associated with QUIC packet-number spaces and session state; it is not a TLS record sequence number or DTLS epoch/sequence pair.

The packet layer owns the packet-number space and protection context; its key derivation inputs and timing are described in Behavior Model. These contexts do not turn QUIC packets into TLS records.

Packet construction combines the packet header, packet-number context, frame payload, and packet-protection output. The order of these operations belongs to Behavior Model.

## 3. Behavior Model

### Initial and TLS-derived packet keys

Initial secrets are derived from the QUIC version's fixed Initial salt and destination connection ID, so Initial protection is available before TLS handshake traffic secrets exist. Handshake and Application packet keys are derived later from TLS 1.3 traffic secrets using QUIC-specific labels. The packet builder consumes the appropriate packet-number space and protection context; these stages do not turn QUIC packets into TLS records.


### Packet assembly and output boundary

```text
TLS handshake bytes -> CRYPTO frame -----+
                                         |
other transport/control frames ----------+-> packet builder
                                             | header + packet number
                                             | frame payload
                                             v
                                  packet protection/publication
                                             |
                                             v
                                       UDP output path
```

The packet builder encodes packet-level structure; the session/publisher supplies the applicable connection state, packet-number space, payload-size constraints, and protection context. Packet bytes are then handed to the transport send path. A frame encoding by itself is not a packet, and the packet publisher is not itself the UDP socket.

The shared `hotplace::io::payload` abstraction describes binary fields where used by the implementation; it does not replace QUIC-specific packet-header rules, packet-number reconstruction, or protection logic.

## 5. Relationships

- `quic_packet.hpp/.cpp`, `quic_packets.hpp/.cpp`, `quic_packet_builder.hpp/.cpp`.
- `quic_packet_initial.*`, `quic_packet_handshake.*`, `quic_packet_0rtt.*`, `quic_packet_1rtt.*`, `quic_packet_retry.*`, `quic_packet_version_negotiation.*`.
- [QUIC overview](../README.md) and [frame implementation](../frame/README.md).
- [QUIC packet publisher](../../quic_packet_publisher.md) and [TLS session support](../../session/README.md).
- `sdk/io/basic/payload.hpp/.cpp` — reusable binary field-layout abstraction where used by packet/frame code.
- `../../protection/` — QUIC Initial derivation from the destination connection ID, later TLS-derived QUIC secrets, and the shared cryptographic protection operations.

## 6. References

- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
