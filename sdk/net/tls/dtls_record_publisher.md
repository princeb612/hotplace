# DTLS record publisher

## Identity

`dtls_record_publisher` is the session-level DTLS 1.2 record construction component. It converts TLS handshake records into DTLS records while applying DTLS-specific handshake fragmentation and record segmentation.

It is exposed through `tls_session::get_dtls_record_publisher()`.

## Construction model

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

The publisher operates on `tls_record` / `tls_records` and uses the session's DTLS message sequence state when constructing fragmented handshake records.

## Fragmentation and segmentation

Two size controls are intentionally separate:

- `set_fragment_size()` controls DTLS handshake fragmentation. The implementation constrains this value to the configured DTLS fragmentation range.
- `set_segment_size()` controls the larger record/output segmentation boundary.

The default values in the implementation are a 1024-byte fragment size and a 1200-byte segment size.

The `dtls_record_publisher_multi_handshakes` flag controls whether multiple handshake messages may be carried together when publishing.

## Interface

- `publish(tls_record*, dir, container)` builds output records into a list.
- `publish(tls_record*, dir, callback)` sends generated records through a callback.
- `publish(tls_records*, dir, callback)` publishes a collection of records.
- `set_fragment_size()` / `get_fragment_size()` configure handshake fragmentation.
- `set_segment_size()` / `get_max_size()` configure the output segment boundary.
- `set_flags()` / `get_flags()` control publisher behavior.

## Session relationship

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

## Related source and tests

- `dtls_record_publisher.hpp`
- `session/dtls_record_publisher.cpp`
- `test/testcase/tls/testcase_construct_dtls12_1.cpp`
- `test/testcase/tls/testcase_construct_dtls12_2.cpp`
- `test/testcase/tls/sample.cpp`

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```
