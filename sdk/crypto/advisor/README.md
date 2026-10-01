# Crypto Advisor

`sdk/crypto/advisor` contains the metadata and lookup layer for cryptographic algorithms, identifiers, parameters, and OpenSSL mappings used throughout hotplace.

The directory does not implement encryption, hashing, signatures, or key exchange itself. Those primitives live under `sdk/crypto/basic`; the advisor tells higher-level code how names and identifiers map to those implementations and to protocol/backend identifiers.

## Documentation

- [crypto_advisor.md](crypto_advisor.md) — advisor architecture, resource tables, lookup domains, OpenSSL mapping, and testcase invariants

## Implementation areas

- `crypto_advisor.*` — public lookup/query interface
- `crypto_advisor_*.cpp` — domain-specific lookup logic
- `resource_*.cpp` — static algorithm/parameter resource tables

## Related tests

- [`test/testcase/crypto/advisor/`](../../../test/testcase/crypto/advisor/README.md)

## Related areas

- [`../basic/`](../basic/README.md) — primitive implementation layer
- [`../cose/`](../cose/README.md) — COSE
- [`../jose/`](../jose/README.md) — JOSE
- [`../../net/tls/`](../../net/tls/README.md) — TLS integration
