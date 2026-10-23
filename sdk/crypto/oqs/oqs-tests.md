## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
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
`testcase_oqs_encode.cpp` enumerates KEM and signature algorithms and exercises private PEM, encrypted private PEM, public PEM, private DER, encrypted private DER, and public DER where the algorithm is OID-registered.

`testcase_oqs_kem.cpp` checks key generation, key serialization, public-key decoding, encapsulation, decapsulation, and shared-secret equality.

`testcase_oqs_dsa.cpp` checks key generation, serialization, public-key decoding, signing, and verification.

## 5. Relationships

### Source-test evidence

The tests require OpenSSL 3 and an externally installed `oqsprovider` module. Algorithms without OID registration are marked `not_supported` by the source test path rather than exercised as normal supported algorithms. The separate `testcase_pqc_*.cpp` sources cover common PQC operations, including hybrid KEM behavior.

No test was run during this documentation pass. The supplied crypto report is aggregate (`crypto` suite: pass 4214, expt 281, fail 0, skip 90); it does not provide an isolated OQS/PQC breakdown, so those totals are not attributed to this directory. The meaning of `expt` and `triv` is not inferred.

- [Provider adapter](oqs-provider-adapter.md)
- [PQC testcase map](../../../test/testcase/crypto/pqc/testcase_pqc.md)
- `test/testcase/crypto/oqs-provider.md` is the separate provider study note.
- `testcase_oqs_encode.cpp`
- `testcase_oqs_kem.cpp`
- `testcase_oqs_dsa.cpp`
- `testcase_pqc_encode.cpp`
- `testcase_pqc_kem.cpp`
- `testcase_pqc_hybrid_kem.cpp`
- `testcase_pqc_dsa.cpp`
