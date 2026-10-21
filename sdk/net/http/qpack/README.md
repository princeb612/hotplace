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
# QPACK implementation

## 1. Role

`qpack` implements the HTTP/3 field compression format. It encodes/decodes header fields and maintains QPACK static/dynamic table state. HTTP/3 frame parsing and QUIC transport/session behavior remain in their own modules.

## 2. Data Model

```text
HTTP/3 HEADERS frame
        │ field section
        ▼
     qpack_encoder
        ├─ QPACK static table
        ├─ QPACK dynamic table
        ├─ field-section prefix (required insert count / base)
        └─ indexed / literal field representations
                 │
                 ▼
          decoded header fields

Separate unidirectional QUIC streams
  QPACK encoder stream -> dynamic-table instructions
  QPACK decoder stream -> acknowledgements / cancellation
```

The principal classes are `qpack_encoder`, `qpack_static_table`, and `qpack_dynamic_table`, built on shared compression/table abstractions. The shared base classes provide common lookup and bookkeeping operations; QPACK-specific encodings, field-section state, and instruction semantics remain distinct. QPACK's static table is not interchangeable with HPACK's static table.

## 3. Behavior Model

### HTTP/3 header field flow

The HTTP/3 frame layer identifies a HEADERS frame and extracts its QPACK field section. QPACK interprets the field-section prefix and field representations against the relevant QPACK context, resolves static/dynamic references, and applies table updates/instructions. The decoded name/value pairs then become part of the HTTP request/response model.

```text
QUIC stream data
  -> HTTP/3 frame parser
  -> HEADERS field section
  -> QPACK decode
       ├─ field-section prefix / required insert count / base
       ├─ static table lookup
       ├─ dynamic table lookup
       └─ literal field representation
  -> decoded header fields
```

### Why QPACK is not HPACK

HTTP/2's HPACK dynamic-table state is tied to the HTTP/2 compression context and header-block ordering. HTTP/3 multiplexes independent QUIC streams, so QPACK coordinates dynamic-table use through dedicated encoder and decoder unidirectional QUIC streams, acknowledgements and cancellation state. A field section may refer to table state that must be synchronized with those instruction paths; it cannot be decoded as an independent text block.

Both protocols use static and dynamic tables, but their indexes, wire representations, update coordination, and decoder behavior differ. Do not share HPACK state or decode QPACK bytes with the HPACK implementation.

The current QPACK classes and testcase vectors show implementation coverage for parts of this format; they do not by themselves establish that the complete HTTP/3 server path is enabled.

## 4. Relationships

- `qpack_encoder.hpp/.cpp` — QPACK field encoding and decoding.
- `qpack_static_table.hpp/.cpp`, `qpack_dynamic_table.hpp/.cpp` — QPACK-specific tables.
- [Shared compression infrastructure](../compression/README.md) — common table and compression abstractions.
- [HTTP/3 frames](../http3/README.md) — HEADERS carries QPACK field sections.
- [QUIC transport](../../tls/quic/README.md) — QUIC streams carry HTTP/3 bytes; QPACK instruction streams are carried within the HTTP/3 connection model.
- [HTTP core model](../http-core-model.md) — decoded fields become HTTP headers.
- [HPACK](../hpack/README.md) — related header compression for HTTP/2, but a different wire format/state machine.
- `test/testcase/net/qpack/testcase_rfc9204.cpp`, `testcase_capacity.cpp`, and `testcase_qpack_stream.cpp` — source-level QPACK vectors and state/capacity/stream assertions.

## 5. References

- [RFC 9204 — QPACK: Field Compression for HTTP/3](https://www.rfc-editor.org/rfc/rfc9204)
