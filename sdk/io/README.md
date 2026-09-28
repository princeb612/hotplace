# IO

The `sdk/io` area contains serialization, parsing, protocol payload, and operating-system I/O related components.

## Directory map

- `asn.1/` — ASN.1 notation, parser integration, loader/compiler/runtime
- `cbor/` — CBOR encoding and RFC examples
- `parser/` — grammar parser and parsing-table infrastructure
- Other IO utilities include multiplexing, payload handling, streams, compression, and protocol-specific encodings.

## Related areas

- `sdk/base/` — encoding, stream, string, and system primitives used by IO components
- `sdk/crypto/` — COSE, JOSE, certificates, and other formats that consume IO/ASN.1 infrastructure
- `sdk/net/` — HTTP/2, QUIC, TLS, and packet payload processing

## Related tests

- `test/testcase/asn.1/`
- `test/testcase/io/parser/`
- `test/testcase/cbor/`

## References

- RFC 7049 — Concise Binary Object Representation (CBOR)
- RFC 8949 — Concise Binary Object Representation (CBOR)
