## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Post-quantum cryptography testcase directory

## 1. Role

This directory contains direct tests for hotplace's PQC abstractions and the optional OQS provider integration. It is a source map; it does not imply that all tests are enabled in every build.

## 2. Test model

The test sources are divided into common PQC operation tests and provider-specific integration tests:

- `testcase_pqc_dsa.cpp` — signature operations
- `testcase_pqc_encode.cpp` — key encoding/decoding
- `testcase_pqc_kem.cpp` — key encapsulation
- `testcase_pqc_hybrid_kem.cpp` — hybrid KEM flow
- `oqs/` — provider enumeration and OQS-specific tests

## 3. Example: provider-backed KEM and signature operations

For provider-backed KEM coverage, the OQS KEM testcase generates keys, serializes and reloads key material, encapsulates with the public key, decapsulates with the private key, then compares the shared secrets. For signature coverage, the OQS DSA testcase signs and verifies with the matching key pair.

## 4. Test and verification status

### 4.1 Source-level coverage

Source-level coverage is represented by the listed C++ test files. The existence of a testcase is not proof it ran in a particular environment. Provider-specific tests require OpenSSL 3 and a loadable `oqsprovider` module; algorithm enumeration and OID registration affect which branches are exercised.

### 4.2 Documentation and verification status

No tests were run during this documentation pass. The supplied aggregate crypto report does not isolate the PQC/OQS directory, so no per-directory result is asserted here.

## 5. Relationships

- [PQC testcase detail map](testcase_pqc.md)
- `oqs/` contains provider-specific tests.
- `sdk/crypto/oqs/` documents the provider adapter.
- `sdk/crypto/basic/` contains common cryptographic abstractions.

## 6. References

- `testcase_pqc_dsa.cpp`
- `testcase_pqc_encode.cpp`
- `testcase_pqc_hybrid_kem.cpp`
- `testcase_pqc_kem.cpp`
- `oqs/testcase_oqs_encode.cpp`
- `oqs/testcase_oqs_kem.cpp`
- `oqs/testcase_oqs_dsa.cpp`
