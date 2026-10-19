## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Crypto Advisor: Lookup Domains and Resource Mapping

## 1. Role

This document describes the implementation details behind [`crypto_advisor`](crypto_advisor.hpp): the lookup domains, resource metadata, and mapping boundary between hotplace's crypto abstractions and identifiers exposed by OpenSSL and protocols.

## 2. Model

The advisor is organized around domain-specific hint/resource tables and query methods. The tables preserve different kinds of information—algorithm names, hotplace enums/schemes, key types, curve aliases, protocol identifiers, and backend references—instead of forcing every domain into one common record.

| Resource area | Representative information |
|---|---|
| Cipher | algorithm/mode, scheme, names, EVP cipher mapping |
| Digest | digest algorithm, names, EVP MD mapping |
| Curve | aliases, key type, OpenSSL NID, TLS group where applicable |
| Key and signature | key/signature metadata and naming/identifier mappings |
| JOSE | JWA/JWE/JWS-related names and metadata |
| COSE | COSE algorithm identifiers and metadata |
| TLS | signature schemes, groups, and TLS-related parameters |

The feature index associates a name with one or more `advisor_feature_t` bits. Flags include cipher, digest, wrapping, JWA, JWE, JWS, COSE, curve, version-specific, signature-scheme, and TLS-group categories.

## 3. Important behavior and lifetime

### Backend resolution is conditional

The existence of a hint does not imply that OpenSSL provides a usable method in the active build. The implementation conditionally populates maps when an EVP cipher or digest can be resolved. Code using `find_evp_cipher()` or `find_evp_md()` must account for a null result.

### OpenSSL version paths

The implementation uses OpenSSL 3 fetch APIs (`EVP_CIPHER_fetch` and related APIs) when compiled against OpenSSL 3. Earlier versions use the corresponding name-based lookup paths and include compatibility handling for selected cipher-wrap methods. These branches describe backend integration, not a guarantee that all listed algorithms are supported in every build.

### Aliases and identifier domains

Curve lookup methods accept names from multiple naming conventions and can map them to the same hint. Other lookup methods translate between hotplace enums/schemes, OpenSSL NIDs or EVP objects, and protocol-specific identifiers. The supported mappings are defined by the current resource data and build environment.

### Feature enumeration

`query_feature()` and the `for_each_*()` family expose resource availability and allow callers/tests to inspect the advertised set without copying the resource tables. The feature index describes known/available mappings; it is not a security-policy evaluator.

## 4. Example from the source tests

The source testcase in [`testcase_advisor.cpp`](../../../test/testcase/crypto/advisor/testcase_advisor.cpp) demonstrates three invariants:

1. Feature enumeration visits the cipher, digest, JOSE, COSE, and curve entries that the advisor advertises.
2. `P-256`, `prime256v1`, and `secp256r1` resolve to the expected same NID in the tested OpenSSL configuration.
3. Cipher resource entries are cross-checked so that their scheme's algorithm/mode agrees with the entry's fetch-name mapping.

These checks protect table consistency. They are not comprehensive cryptographic known-answer tests, protocol conformance tests, or a claim that every listed algorithm is enabled in every build.

## 5. Relationships

- [`README.md`](README.md) — directory-level role and file map.
- [`../basic/`](../basic/README.md) — cryptographic operations and core types.
- [`../cose/`](../cose/README.md) and [`../jose/`](../jose/README.md) — protocol/object formats whose identifiers are represented in advisor data.
- [`../../net/tls/`](../../net/tls/README.md) — TLS integration.
- [`../../../test/testcase/crypto/advisor/`](../../../test/testcase/crypto/advisor/README.md) — advisor-specific tests.

## 6. References

- [`crypto_advisor.hpp`](crypto_advisor.hpp) — public methods, hint lookup APIs, and feature flags.
- [`crypto_advisor.cpp`](crypto_advisor.cpp) — initialization and mapping construction.
- `crypto_advisor_*.cpp` — domain-specific lookup implementation.
- `resource_*.cpp` — static metadata tables.
