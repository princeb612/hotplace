## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Crypto Advisor Testcases

## 1. Role

This directory contains source-level tests for the metadata and lookup interface implemented in [`sdk/crypto/advisor`](../../../../sdk/crypto/advisor/README.md). The tests focus on consistency of advertised features and resource mappings, not on implementing or benchmarking cryptographic primitives.

## 2. Test model

[`testcase_advisor.cpp`](testcase_advisor.cpp) groups checks into feature enumeration, curve alias lookup, and resource consistency. It uses the shared crypto testcase support from `testcase/crypto/sample.hpp` and the project's testcase assertion/reporting helpers.

The tests are dependent on the active OpenSSL build: backend availability and version-specific mappings can affect which resources are resolved. A source assertion documents an expected invariant, but does not by itself establish that the test was executed in a particular environment.

## 3. Example: curve aliases resolve to the same metadata

The curve test queries `P-256`, `prime256v1`, and `secp256r1`, then checks that each returned hint has NID `415` in the source's expected configuration. This is a concrete alias-consistency check rather than a full test of elliptic-curve arithmetic.

## 4. Test and verification status

### 4.1 Source-level coverage

- Enumerates cipher, digest, JWA, JWE, JWS, COSE, and curve feature sets.
- Prints the advisor's feature flags for inspection.
- Checks representative curve aliases against the expected NID.
- Cross-checks cipher scheme algorithm/mode information against the associated resource/fetch-name metadata.

### 4.2 Documentation and verification status

This document was prepared from the Revision 1104 source tree. The testcase source was inspected, but it was **not rerun as part of this documentation update**. No execution result or environment-specific pass status is claimed here.

## 5. Relationships

- [`sdk/crypto/advisor/`](../../../../sdk/crypto/advisor/README.md) — implementation and lookup contract.
- [`test/testcase/crypto/`](../README.md) — shared crypto testcase area and supporting material.
- [`sdk/crypto/basic/`](../../../../sdk/crypto/basic/README.md) — crypto primitives and types that the metadata describes.

## 6. References

- [`testcase_advisor.cpp`](testcase_advisor.cpp) — source of the checks described above.
- [`sample.hpp`](../sample.hpp) — shared crypto testcase support.
