# QUIC packet publisher

## Identity

`quic_packet_publisher` is the session-level QUIC packet construction component. It collects TLS handshake messages, QUIC frames, HTTP/3 frames, and QPACK stream data, then packs them into QUIC packets according to the applicable protection space and payload limit.

It is exposed through `tls_session::get_quic_packet_publisher()`.

## Construction model

```text
TLS handshake
QUIC frame
HTTP/3 frame
QPACK stream
       |
       v
quic_packet_publisher::add()
       |
       v
pending layout / handshake collection
       |
       v
publish(dir)
       |
       +-- probe protection spaces
       |
       +-- build CRYPTO / STREAM / QUIC frames
       |
       +-- segment entries to packet payload limits
       |
       +-- prepare packet connection ID
       |
       +-- optional ACK / PADDING
       |
       +-- write protected packet
       |
       v
QUIC packet output
```

The publisher is therefore a construction boundary between higher-level TLS/HTTP/3 content and the QUIC packet/frame layer.

## Protection spaces

`publish()` first determines which QUIC protection spaces contain pending work. The implementation publishes each relevant space separately, including:

- Initial
- Handshake
- Application / 1-RTT

TLS handshake messages are encoded into QUIC CRYPTO frames for their applicable protection space. Application-space content can additionally become QUIC STREAM frames carrying HTTP/3 or QPACK data.

## Payload segmentation

`set_payload_size()` defines the publisher's packet payload target. Internally, pending data is converted into segment entries and consumed while packet payload capacity remains.

This is intentionally different from `dtls_record_publisher::set_fragment_size()`: QUIC segmentation is driven by packet payload capacity and frame construction rather than DTLS handshake fragmentation.

## Accepted content

The publisher can queue:

- TLS handshake messages with `add(tls_handshake_type_t, ...)`
- QUIC frames with `add(quic_frame_t, ...)`
- HTTP/3 stream frames with `add_stream(stream_id, uni_type, h3_frame_t, ...)`
- QPACK encoder/decoder stream data with `add_stream(stream_id, uni_type, ...)`

`set_flags()` supports packet-level behavior such as ACK and PADDING generation.

## Consumption

`consume(quic_packet*, paid, callback)` provides the corresponding packet-payload segmentation path. It determines the protection space from the packet type, calculates available payload capacity, and exposes segments through the callback.

## Session relationship

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

## Related source

- `quic_packet_publisher.hpp`
- `session/quic_packet_publisher.cpp`
- `quic/packet/README.md`
- `quic/README.md`
- `quic-tls-integration.md`
- `tls-session` / QUIC session handling

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```
