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
# HTTP header compression infrastructure

## 1. Role

`sdk/net/http/compression` provides shared table and compression-stream abstractions used by HPACK and QPACK. It is infrastructure for matching, selecting, inserting, indexing, and maintaining header fields; it does not define the complete wire format of either compression protocol and does not frame HTTP messages.

## 2. Data Model

### Static and dynamic tables

- **Static table:** predefined entries that do not change during a connection. `http_static_table` provides shared lookup/selection structure; protocol-specific subclasses supply their own entries. HPACK and QPACK static tables are distinct protocol-defined tables.
- **Dynamic table:** mutable compression context associated with the relevant connection/compression state. `http_dynamic_table` represents capacity and insertion/drop state and is specialized by `hpack_dynamic_table` and `qpack_dynamic_table`.
- **Compression stream/support:** `http_header_compression` and `http_header_compression_stream` provide common interfaces and state for version-specific encoders/decoders. Protocol-specific flags and instruction semantics remain in HPACK/QPACK.

Exact/name-only matching, indexed selection, insertion, commit, and eviction are state transitions and are described in Behavior Model.

## 3. Behavior Model

### Table lookup and state updates

The encoder attempts to represent a header field with an available index where possible; otherwise it emits a literal representation and may update the dynamic table according to the protocol and flags. Decoding resolves indexes against the corresponding static/dynamic context and applies table updates in the required order. The same encoded index cannot be interpreted independently of the compression context and protocol.

```text
(name, value) field
       │
       ▼
compression algorithm
  ├─ static table: fixed protocol-defined entries
  └─ dynamic table: context-specific entries
       ├─ match exact name + value
       ├─ match name only
       ├─ select by compression index
       ├─ insert / commit updates
       └─ capacity and eviction bookkeeping
```

This diagram captures the shared table-operation vocabulary at field level. The exact index rules, update ordering, and dynamic-table synchronization remain protocol-specific: HPACK maintains its connection compression context, while QPACK additionally coordinates dynamic references through its instruction streams and acknowledgements.

```text
HTTP/2 HEADERS -> HPACK encoder/decoder -> HPACK tables
                                      -> header block bytes

HTTP/3 HEADERS -> QPACK encoder/decoder -> QPACK tables
                                       -> field section bytes
                    │
                    └─ QPACK instruction streams / acknowledgements
                       coordinate dynamic references across QUIC streams
```

HPACK and QPACK share the broad static/dynamic table idea, not a common state machine or wire encoding.

- **HPACK** is coupled to HTTP/2's connection-level framing and compression context. The HTTP/2 layer decides when a header block begins and continues; HPACK encodes/decodes the fields and updates its dynamic table.
- **QPACK** is designed for HTTP/3's multiplexed QUIC streams. It includes encoder/decoder instructions, acknowledgements/cancellation and field-section state so dynamic references can be coordinated despite independent streams. It is not HPACK with a different name.
- **Body content encoding** such as gzip/deflate is unrelated to this module: header compression operates on header fields, not response body bytes.

## 5. Relationships

- `http_header_compression.hpp/.cpp` — shared compression operations and decode data.
- `http_header_compression_stream.hpp` — compression-stream abstraction.
- `http_static_table.hpp/.cpp` — base lookup/select behavior for protocol-specific static tables.
- `http_dynamic_table.hpp/.cpp` — mutable dynamic-table behavior and capacity/entry bookkeeping.
- [HPACK](../hpack/README.md) — HTTP/2 field compression.
- [QPACK](../qpack/README.md) — HTTP/3 field compression.
- [HTTP/2 frames and session](../http2/README.md) and [HTTP/3 frames](../http3/README.md) — the protocol layers that carry compressed header blocks/field sections.
- `../../../../test/testcase/net/hpack/` and `../../../../test/testcase/net/qpack/` — source-level vectors and behavior tests.

## 6. References

- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541)
- [RFC 9204 — QPACK: Field Compression for HTTP/3](https://www.rfc-editor.org/rfc/rfc9204)
