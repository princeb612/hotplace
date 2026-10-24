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

### `quic_param_max_udp_payload_size` and packet sizing

The QUIC session setting `quic_param_max_udp_payload_size` is the publisher's configured payload ceiling. In this implementation, `quic_session` initializes it to **1200 bytes**. `quic_packet_publisher::set_session()` copies the current setting into `_payload_size`, while each `quic_packet` obtains its `get_max_payload_size()` directly from the session setting. The parameter therefore affects packet layout through the session setting; it is not merely a transport-parameter value written into the TLS extension.

```text
quic_session::get_setting()
  quic_param_max_udp_payload_size = 1200 (default)
                 |
                 +-------------------------------+
                 |                               |
                 v                               v
quic_packet_publisher::set_session()      quic_packet::get_max_payload_size()
  _payload_size = current setting           reads session setting directly
                 |                               |
                 |                      publish_space() / consume()
                 |                               |
                 +--> container grouping         v
                      threshold             available payload budget
                                            minus estimated overhead
                                            and already carried bytes
                                                   |
                                                   v
                                       consume CRYPTO / STREAM entries
                                       into packet frame layout
                                                   |
                                                   v
                                       serialize and protect QUIC packet
```

#### How the configured limit changes the layout

1. **Session setup:** the session starts with `quic_param_max_udp_payload_size = 1200`. Code may change the setting through `session->get_quic_session().get_setting().set(quic_param_max_udp_payload_size, value)`. Set it before constructing/publishing packets so the publisher's cached `_payload_size` and the packet's session-backed limit agree.
2. **Available capacity:** `publish_space()` builds a packet for the relevant protection space and calculates `payload_space` from `packet->get_max_payload_size() - packet->estimate_overhead() - bin.size()`. The current `quic_packet::estimate_overhead()` returns zero, so it does not currently subtract a separately estimated header/protection overhead at this stage.
3. **Frame selection:** pending CRYPTO or STREAM entries are added while the accumulated remaining entry bytes have not reached the calculated `payload_space`. The frame and packet serializers still encode their own headers and protection fields; the payload-size setting is a layout budget, not a promise that every final encoded packet is exactly that size.
4. **Multiple packets:** when pending content exceeds the available budget, remaining segments are emitted through subsequent packets. `consume()` uses the same session-backed maximum, subtracting the caller-supplied `paid` bytes and the packet's estimated overhead before reporting a segment limit.
5. **Container grouping:** `_payload_size` is also used when deciding whether the last already-built byte buffer in `container` can be reused as a base for the next protection-space output. This is a separate grouping step; the primary per-packet maximum is read by `quic_packet::get_max_payload_size()` from the session setting.

#### Important distinction: peer limit, local limit, and path MTU

`max_udp_payload_size` is an endpoint's declaration of the maximum UDP payload it is willing to **receive**; the peer must respect the value it learned for the receiver. It is not, by itself, path-MTU discovery. The QUIC implementation's setting is used here as a packet-construction ceiling, but the path may support less or more. RFC 9000 requires support for at least 1200-byte UDP payloads, prohibits IP-layer fragmentation of QUIC datagrams, and describes PMTUD/DPLPMTUD for discovering larger path sizes. Values below 1200 are invalid under the RFC. See [RFC 9000, Section 14](https://www.rfc-editor.org/rfc/rfc9000.html#section-14) and [Section 18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2).

Thus, increasing this setting does not prove that the path can carry larger datagrams, and reducing it does not automatically implement path-MTU discovery. It changes the implementation's configured sizing budget; correctness still depends on peer parameters, packet overhead, and path capacity.
## 4. Relationships
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

## 5. References
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
