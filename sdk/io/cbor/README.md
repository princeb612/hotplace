# CBOR

`sdk/io/cbor` implements a compact CBOR object model, reader/parser, encoder, publisher, and diagnostic/concise visitors.

The directory is used as the project's CBOR representation layer rather than as a general CBOR tutorial.

## Documents

- [CBOR object model](cbor-object-model.md)
- [CBOR reader and encoder](cbor-reader-encoder.md)
- [CBOR visitors](cbor_visitor.md)
- [RFC 8949 Appendix A examples](rfc8949-examples.md)

## Implementation map

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

## Related areas

- `sdk/crypto/cose/` — COSE uses CBOR as its message encoding
- `sdk/base/encoding/` — common encoding facilities
- `sdk/base/system/` — `bignumber` and numeric representation used by CBOR values

## Related tests

- `test/testcase/cbor/testcase_rfc7049.cpp`
- `test/testcase/cbor/testvector_cbor.cpp`
- `test/testcase/cbor/testvector_cbor.yml`
- `test/testcase/cbor/sample.cpp`

## References

- RFC 7049 — Concise Binary Object Representation
- RFC 8949 — Concise Binary Object Representation
