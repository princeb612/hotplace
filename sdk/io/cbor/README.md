## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1105                     │
│ Source basis: Revision 1105                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```

# CBOR

## 1. Role

The directory provides the CBOR value tree and conversion paths between encoded bytes, object values, and readable representations. It is a format-specific subsystem, not a wrapper around the generic grammar parser.

## 2. Data Model

`sdk/io/cbor` implements a compact CBOR object model, reader/parser, encoder, publisher, and diagnostic/concise visitors.

The directory is used as the project's CBOR representation layer rather than as a general CBOR tutorial.

### Implementation map

```text
input
  │
  ├── binary / diagnostic expression
  │
  ▼
cbor_reader
  │
  ▼
cbor_object tree
  ├── cbor_data
  ├── cbor_array
  ├── cbor_map
  ├── cbor_pair
  ├── cbor_bstrings
  ├── cbor_tstrings
  └── cbor_simple
  │
  ├── cbor_publisher
  ├── cbor_concise_visitor
  └── cbor_diagnostic_visitor
```

`cbor_encode` provides the reverse direction from values/objects to CBOR binary.

## 3. Behavior Model

The logical CBOR object model is distinct from its encoded byte layout. Readers construct object values, while encoders and publishers produce output representations.

### Conversion path

The main conversion path is encoded bytes → `cbor_reader` → `cbor_object` tree → binary/concise or diagnostic representation. `cbor_encode` provides the reverse direction from values/objects to CBOR bytes. RFC-oriented vectors and sample object construction are located under `test/testcase/cbor/`; this directory overview does not claim those tests were run during the documentation update.

## 4. Relationships

### Component documents

- [CBOR object model](cbor-object-model.md) — object/value representation.
- [CBOR reader and encoder](cbor-reader-encoder.md) — conversion between CBOR bytes and objects.
- [CBOR visitors](cbor_visitor.md) — readable and diagnostic representations.
- [RFC 8949 Appendix A examples](rfc8949-examples.md) — retained specification-oriented examples.

### Related areas

- `sdk/crypto/cose/` — COSE uses CBOR as its message encoding
- `sdk/base/encoding/` — common encoding facilities
- `sdk/base/system/` — `bignumber` and numeric representation used by CBOR values

### Related tests

- [CBOR testcase sources and vectors](../../../test/testcase/cbor/) — RFC 7049 examples, CBOR vectors, and sample object construction.

## 5. References

- [RFC 7049 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc7049), the earlier specification used by retained examples.
- [RFC 8949 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949), the current CBOR specification.
