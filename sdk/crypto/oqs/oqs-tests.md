## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# OQS provider test coverage

## 1. Role

This record maps the provider adapter's direct test sources to the operations they exercise.

## 2. Data Model
The OQS tests are integration tests around provider discovery and OpenSSL key/operation APIs. They are not a NIST/ACVP known-answer test suite.

## 3. Behavior Model
`testcase_oqs_encode.cpp` enumerates KEM and signature algorithms and exercises private PEM, encrypted private PEM, public PEM, private DER, encrypted private DER, and public DER where the algorithm is OID-registered. It checks encode/decode statuses but does not compare the reconstructed key objects.

`testcase_oqs_kem.cpp` checks key generation, public/private key serialization, public-key decoding, encapsulation, decapsulation, and byte-for-byte shared-secret equality. It does not decode the encoded private key.

`testcase_oqs_dsa.cpp` checks key generation, public/private serialization, public-key decoding, signing, and verification for the same message. It is not a fixed signature-vector or negative-message test.

## 4. Relationships

### Source-test evidence

The tests are selected by the `SUPPORT_OQS` build option: when enabled, `pqc/oqs/*.cpp` is compiled; otherwise the `pqc/dummy/*.cpp` implementations are selected. An OQS-enabled build still requires OpenSSL 3 and an externally installed `oqsprovider` module at runtime. Algorithms without OID registration are marked `not_supported` by the source test path rather than exercised as normal supported algorithms. The separate `testcase_pqc_*.cpp` sources cover common PQC operations, including hybrid KEM behavior.

The current branch does not contain the referenced `test/testcase/crypto/report` file, and no aggregate report is available here to substantiate a pass/expt/fail/skip total. No test was run during this documentation pass; therefore no OQS/PQC result is asserted.

- [Provider adapter](oqs-provider-adapter.md)
- [PQC testcase README](../../../test/testcase/crypto/pqc/README.md)
- `test/testcase/crypto/oqs-provider.md` is the separate provider study note.
- `testcase_oqs_encode.cpp`
- `testcase_oqs_kem.cpp`
- `testcase_oqs_dsa.cpp`
- `testcase_pqc_encode.cpp`
- `testcase_pqc_kem.cpp`
- `testcase_pqc_hybrid_kem.cpp`
- `testcase_pqc_dsa.cpp`
