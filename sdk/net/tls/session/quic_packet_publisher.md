## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# QUIC packet publisher

## 1. Role

This document records the session-level QUIC send-side adapter that composes TLS handshake data and application/HTTP/3 stream content into protected QUIC packets.

## 2. Data Model

### Pending content and packet layout

The publisher is a session-level adapter, not a packet or frame serializer. Its pending state accepts multiple content types and maps them to QUIC frames according to packet protection space:

| Input | Intermediate representation | Output frame family |
|---|---|---|
| TLS handshake message | Encoded handshake bytes, associated with handshake stage | CRYPTO |
| QUIC frame | Frame object / encoded frame | That QUIC frame type |
| HTTP/3 frame on a stream | Stream ID, unidirectional-stream type, encoded HTTP/3 frame | STREAM carrying HTTP/3 bytes |
| QPACK encoder/decoder data | Stream ID, stream type and byte content | STREAM |
| Publisher flags | ACK/PADDING options | Optional ACK or PADDING frame where applicable |

The publisher is associated with a tls_session and initializes its payload target from the QUIC session's max_udp_payload_size parameter. The payload target is not the same as the UDP datagram size guarantee for every path: packet headers, frame encodings, protection overhead, and packet type affect the final layout.

### Construction model

~~~text
pending handshake / frame / stream data
  -> quic_packet_publisher
  -> select Initial / Handshake / Application Data work
  -> encode handshake bytes as CRYPTO frames
  -> encode stream content as STREAM frames
  -> segment entries under available payload capacity
  -> construct packet header / connection ID
  -> optional ACK / PADDING
  -> packet builder and protection
  -> callback receives packet bytes
~~~

TLS handshake bytes use CRYPTO frames; application and HTTP/3/QPACK stream bytes use STREAM frames. The packet/frame layer owns actual wire serialization and protection details.

## 3. Behavior Model

### Publish flow

1. The publisher receives content through one of the add methods. Handshake objects, generic QUIC frames, HTTP/3 stream frames, and QPACK stream bytes remain distinguishable until packet layout is chosen.
2. At publish time, it probes pending work by protection space and publishes relevant Initial, Handshake, and Application Data packets separately. It does not wrap these contents in TLS records.
3. Handshake messages are serialized and mapped to CRYPTO-frame data for the appropriate handshake space. Stream/application data is mapped to STREAM frames in the application space.
4. The publisher consumes layout entries while packet payload capacity remains. The remaining capacity depends on the packet type/header, frame encoding, configured payload target, and protection overhead.
5. The packet builder creates the packet header and frame payload; the packet protection path applies the correct QUIC encryption and header protection. The publisher then emits the resulting packet bytes through the supplied callback/output boundary.

The consume path is the reverse segmentation adapter for an already constructed QUIC packet payload: it selects the relevant protection space from packet type, calculates available payload capacity, and exposes payload segments through the callback.

### Scope boundary

The publisher orchestrates content-to-frame and frame-to-packet layout. It does not replace QUIC frame/packet classes, implement the TLS key schedule itself, or send a UDP datagram on its own. Successful callback output proves local packet construction only, not delivery, ACK/loss recovery, or interoperability.

## 5. Relationships
- `quic_packet_publisher.hpp`
- `session/quic_packet_publisher.cpp`
- `quic/packet/README.md`
- `quic/README.md`
- `quic-tls-integration.md`
- `tls-session` / QUIC session handling
- [TLS/DTLS/QUIC overview](../README.md)
- [QUIC implementation](../quic/README.md)
- [TLS/QUIC integration](../quic-tls-integration.md)
- [TLS session support](README.md)
- [Network session model](../../server/network_session.md)

### Session relationship

```text
tls_session
    |
    +-- QUIC session
    |
    +-- quic_packet_publisher
           |
           +-- TLS handshake -> CRYPTO frame
           +-- QUIC frame
           +-- HTTP/3 -> STREAM frame
           +-- QPACK -> STREAM frame
           |
           v
       QUIC packet
```

The publisher does not replace QUIC packet/frame classes. It orchestrates their construction and packing for a session.

## 6. References
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
