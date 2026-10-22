## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# PQC testcase source map

## 1. Role

This document maps the common PQC testcase sources and the nested OQS integration tests to their tested behavior.

## 2. Test model

1. The suite covers key serialization, KEM, signatures, and a hybrid KEM path. Provider-specific tests are under `oqs/`; common PQC tests are directly under this directory.

## 3. Example: provider-backed KEM and signature operations

```text
common PQC tests
 ├── encode / decode
 ├── KEM encapsulate / decapsulate
 ├── hybrid KEM
 └── signature operations

OQS provider tests
 ├── provider algorithm enumeration + key serialization
 ├── KEM shared-secret comparison
 └── signature sign / verify
```

## 4. Test and verification status

### 4.1 Source-level coverage

- `testcase_pqc_encode.cpp`: common key encoding/decoding coverage.
- `testcase_pqc_kem.cpp`: KEM operations.
- `testcase_pqc_hybrid_kem.cpp`: hybrid KEM flow.
- `testcase_pqc_dsa.cpp`: signature operations.
- `oqs/testcase_oqs_encode.cpp`: enumerates provider KEM/signature algorithms; attempts six PEM/DER encoding variants for OID-registered entries.
- `oqs/testcase_oqs_kem.cpp`: checks encapsulated/decapsulated shared-secret equality.
- `oqs/testcase_oqs_dsa.cpp`: checks signing and verification.

### 4.2 Documentation and verification status

No tests were executed during this documentation update. The available report gives aggregate crypto totals only (pass 4214, expt 281, fail 0, skip 90); it does not identify a standalone PQC/OQS result. OpenSSL version and provider installation influence OQS test availability. No source or test code was modified.

## 5. Relationships

- [SDK OQS overview](../../../../sdk/crypto/oqs/README.md)
- [OQS test details](../../../../sdk/crypto/oqs/oqs-tests.md)
- `../` contains the other crypto testcase groups.

## 6. References

- `testcase_pqc_dsa.cpp`
- `testcase_pqc_encode.cpp`
- `testcase_pqc_hybrid_kem.cpp`
- `testcase_pqc_kem.cpp`
- `oqs/testcase_oqs_encode.cpp`
- `oqs/testcase_oqs_kem.cpp`
- `oqs/testcase_oqs_dsa.cpp`
