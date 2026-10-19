## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# JOSE test resources

## 1. Role

This directory contains direct testcase sources, JOSE samples, RFC example fixtures, JWK/PEM keys, and algorithm test vectors for `sdk/crypto/jose`. It is test data and executable source, not a separate JOSE implementation.

## 2. Test model

The suite is organized by RFC and capability:

- RFC 7515 — JWS signing/verification and serialization forms.
- RFC 7516 — JWE examples.
- RFC 7517 — JWK handling.
- RFC 7518 — JWA algorithm cases.
- RFC 7520 — broad JWS/JWE examples and combinations.
- RFC 7638 — JWK thumbprints.
- RFC 8037 — ECDH and EdDSA-related JOSE support.
- AKP — ML-DSA-oriented signing vectors, gated by OpenSSL version in the source.

## 3. Example: RFC 7515 A.1 JWS

`testcase_rfc7515.cpp::test_rfc7515_A1()` loads `rfc7515.jwk`, signs the RFC's HS256 header and payload, and checks the compact JWS string against the expected RFC output. It also exercises flattened and general JSON serializations and verification calls. This is a concrete example of protocol-level serialization being checked around a common MAC operation.

## 4. Test and verification status

### 4.1 Source-level coverage

| Source | Coverage indicated by source | Data / vectors |
|---|---|---|
| `testcase_rfc7515.cpp` | JWS sign/verify, compact/flattened/general JSON, PEM and key-generation paths | `rfc7515.jwk`, `rfc7515.pem`, RFC 7515 fixtures |
| `testcase_rfc7516.cpp` | JWE RFC examples and key-management/content-encryption cases | `rfc7516_A*.jwk/.jws` and related fixtures |
| `testcase_rfc7517.cpp` | JWK examples | JWK fixture files |
| `testcase_rfc7518.cpp` | JWA algorithm cases including RSA-PSS | RFC 7518 key fixtures |
| `testcase_rfc7520.cpp` | JWS/JWE examples, nested content, JSON/flattened JWE | `rfc7520_figure*.jws/.jwe`, public/private JWKs |
| `testcase_rfc7638.cpp` | JWK thumbprint example | `rfc7638_3.jwk` |
| `testcase_rfc8037.cpp` | ECDH/EdDSA feature cases | X25519, X448, Ed25519 JWKs |
| `testcase_akp.cpp`, `testvector_akp.cpp` | ML-DSA sign/verify and JSON test vectors | `testvector_akp_mldsa44.json`, `...65.json`, `...87.json` |

The `testcase_akp.cpp` implementation explicitly requires OpenSSL 3.5 for its ML-DSA branch; otherwise it records `not_supported`. The testcase directory also includes `sample.cpp/.hpp` and `CMakeLists.txt`.

### 4.2 Documentation and verification status

The supplied `testcase-reports.zip` records the JOSE suite in **MinGW64**, for **source revision 1104** as clarified by the maintainer. Its summary is:

| Report group | pass | expt | fail | skip | triv |
|---|---:|---:|---:|---:|---:|
| JOSE total | 295 | 0 | 0 | 0 | 2 |

The report's RFC 7515 group records `success 34, triv 2`; RFC 7520 records `success 164`, and RFC 8037 records `success 30`. The terms `expt` and `triv` are reproduced without inferring framework semantics. These are supplied report results, not a new test run performed during documentation work.

## 5. Relationships

- `../../../sdk/crypto/jose/` contains the implementation documented by these tests.
- `../../sdk/crypto/basic/` supplies the cryptographic primitives and key abstractions.
- `../../sdk/crypto/advisor/` provides common algorithm/resource metadata.
- `../../sdk/crypto/cose/` has related security-object functionality using CBOR and COSE-specific identifiers.

## 6. References

- [JOSE implementation overview](../../../sdk/crypto/jose/jose-overview.md)
- [JWS/JWE processing](../../../sdk/crypto/jose/jose-signing-encryption.md)
- [JWK and algorithm mapping](../../../sdk/crypto/jose/jose-key-and-algorithms.md)
