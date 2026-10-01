# I/O Basic

`sdk/io/basic` contains common data and utility mechanisms used by higher-level I/O and protocol code.

It is deliberately smaller in scope than `sdk/base`: these facilities are oriented toward binary message representation, I/O-side identifiers, compression, and lightweight data-format helpers.

## Main components

| Component | Role | Document |
|---|---|---|
| `payload` | Declarative binary message layout, read/write, groups, references and conditional fields | [payload.md](payload.md) |
| `oid` | Dotted OID string ↔ node-vector conversion | [oid.md](oid.md) |
| `zlib` | zlib / DEFLATE / gzip wrapper | [zlib.md](zlib.md) |
| `json` | Thin Jansson parsing helpers | [json.md](json.md) |
| `types` | Forward declarations and common I/O basic types | source-only support |

## Position in the SDK

```text
sdk/base
    |
    v
sdk/io/basic
    |
    +---- payload / representation helpers
    +---- OID conversion
    +---- compression wrapper
    +---- JSON parsing helper
    |
    v
higher-level I/O and protocol modules
```

`payload` is the central implementation in this directory. It is used to describe protocol binary layouts without introducing a protocol-specific schema language. Its field values are backed by the base `variant`/numeric abstractions, while specialized variable-length encodings can be supplied through `payload_encoded`.

## Related areas

- `sdk/base/basic/` — common value and memory abstractions
- `sdk/base/system/` — numeric and runtime support used by payload
- `sdk/io/asn.1/` — ASN.1-specific object/encoding model
- `sdk/io/parser/` — parser infrastructure used by higher-level notation parsers
- `sdk/io/system/` — I/O-specific types used by payload and other modules
- `sdk/net/` — protocol implementations consuming these common facilities

## Tests

The direct basic-I/O tests are under `test/testcase/io/basic/`:

- `testcase_payload.cpp`
- `testcase_payload_quic.cpp`

The payload tests cover the main implemented behavior of this directory, including binary round trips, references, groups, conditional fields, 24/48-bit integers and QUIC encoded integers.

## Source map

- `payload.hpp/.cpp`
- `oid.hpp/.cpp`
- `zlib.hpp/.cpp`
- `json.hpp`
- `types.hpp`

The README is the directory anchor; implementation-specific details belong in the component documents above.
