## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# DTLS record publisher

## 1. Role

This document records the session-level send-side adapter that takes the shared TLS handshake record representation and constructs DTLS-specific records, including handshake fragmentation and record segmentation.

## 2. Data Model

### Identity

`dtls_record_publisher` is the session-level DTLS 1.2 record construction component. It converts TLS handshake records into DTLS records while applying DTLS-specific handshake fragmentation and record segmentation.

It is exposed through `tls_session::get_dtls_record_publisher()`.

### Construction model

```text
TLS handshake records
        |
        v
dtls_record_publisher::publish()
        |
        +-- validate DTLS session
        |
        +-- split handshake messages
        |      according to fragment size
        |
        +-- build DTLS handshake fragments
        |
        +-- segment records
        |      according to configured size
        |
        v
binary DTLS records
        |
        v
callback / output container
```

The publisher operates on `tls_record` / `tls_records` and uses the session's DTLS message sequence state when constructing fragmented handshake records. For handshake records, `publish()` serializes each handshake, removes the ordinary handshake header, and feeds the body to `splitter` with a descriptor carrying the handshake type and sequence number. The splitter callback uses fragment offsets/lengths and boundary flags to create DTLS records and attach `dtls_handshake_fragmented` objects.

### Fragmentation and segmentation

Two size controls are intentionally separate:

- `set_fragment_size()` controls DTLS handshake fragmentation. The implementation constrains this value to the configured DTLS fragmentation range.
- `set_segment_size()` controls the larger record/output segmentation boundary.

The default values in the implementation are a 1024-byte fragment size and a 1200-byte segment size.

The `dtls_record_publisher_multi_handshakes` flag controls whether multiple handshake messages may be carried together when publishing. Without this flag, a new handshake source group is also a record boundary, even when the fragment-size boundary alone would permit sharing a record.

### Interface

- `publish(tls_record*, dir, container)` builds output records into a list.
- `publish(tls_record*, dir, callback)` sends generated records through a callback.
- `publish(tls_records*, dir, callback)` publishes a collection of records.
- `set_fragment_size()` / `get_fragment_size()` configure handshake fragmentation.
- `set_segment_size()` / `get_max_size()` configure the output segment boundary.
- `set_flags()` / `get_flags()` control publisher behavior.

## 3. Behavior Model

The publisher is retrieved from the active `tls_session`, so its message-sequence and size decisions are tied to session state. Fragment size and output segment size are separate controls: the first divides a handshake body into DTLS fragments through `splitter`; the second bounds later output-record segmentation/grouping. `dtls_handshake_fragmented::prepare_fragment()` retains the original handshake sequence and selects the body slice using fragment offset and length. Publishing output does not perform receive-side reordering, which is handled by `dtls_record_arrange`.

## 4. Relationships


- [TLS/DTLS/QUIC overview](README.md)
- [DTLS record arrangement](dtls_record_arrange.md)
- [TLS session support](session/README.md)
- [Network session model](../server/network_session.md)
### Session relationship

```text
tls_session
    |
    +-- dtls_record_publisher
    |      |
    |      +-- TLS handshake record
    |      +-- DTLS handshake fragmentation
    |      +-- record segmentation
    |
    +-- dtls_record_arrange
    |      +-- receive-side reordering
    |
    +-- protection / record layer
```

The publisher is the **send-side construction** counterpart to `dtls_record_arrange`, which performs receive-side ordering.

### Implementation and source examples

- `dtls_record_publisher.hpp` and `session/dtls_record_publisher.cpp` — public interface and the serialization/splitter callback path.
- `tls/handshake/dtls_handshake_fragmented.cpp` — writes the fragment header and selected handshake-body bytes.
- `test/testcase/tls/testcase_construct_dtls12_1.cpp` and `testcase_construct_dtls12_2.cpp` — construction examples; `test/testcase/tls/sample.cpp` contains additional usage examples.

## 5. References

- [RFC 6347 — Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347) — protocol context for DTLS handshake and record fragmentation.
