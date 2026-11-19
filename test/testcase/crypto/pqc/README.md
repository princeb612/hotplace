## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Post-quantum cryptography testcase directory

## 1. What

This directory contains direct tests for hotplace's PQC abstractions and the optional OQS provider integration. It is a source map; it does not imply that all tests are enabled in every build.

## 2. How

### Procedure: common PQC signature placeholder

`testcase_pqc_dsa.cpp` is not yet an implemented common PQC signature test. Its OpenSSL 3.5+ branch contains only `// TODO`; before OpenSSL 3.5 it records `not_supported`. Do not describe this source as executing key generation, signing, or verification. The provider-backed OQS signature path is separate and lives under `pqc/oqs/testcase_oqs_dsa.cpp`.

### Procedure: ML-KEM key encoding and decoding

1. `testcase_pqc_encode.cpp` generates ML-KEM-512/768/1024 key pairs and exercises RAW private/public encode/decode paths under the OpenSSL 3.5+ guard.
2. It checks operation statuses and verifies that the generated key is private and the decoded public key is not private. It does not compare the original and decoded key objects; the decoded private-key object is not otherwise inspected.
3. `testcase_pqc_kem.cpp` separately encodes/decodes public keys in DER and RAW forms, then compares the DER-decoded and RAW-decoded public-key objects with `EVP_PKEY_eq()`. Successful decoding alone does not prove canonical encoding or full parameter preservation.

### Procedure: run the common ML-KEM path

1. The testcase runs ML-KEM-512, ML-KEM-768 and ML-KEM-1024 only under its OpenSSL 3.5-or-later guard.
2. Generate a key pair and check the operation status.
3. Encode/decode the public key through the supported DER form and raw form; compare reconstructed public-key objects where the source does so.
4. Encapsulate to obtain a ciphertext and sender shared secret, then decapsulate with the private key to obtain the receiver shared secret.
5. Compare the two shared-secret buffers. Logged ciphertexts/secrets are diagnostic, not fixed known-answer values.

### Procedure: hybrid ECDHE-ML-KEM key agreement

1. Run the standalone classical X25519 + ML-KEM-768 key-share composition from draft-ietf-tls-ecdhe-mlkem/01 when the required OpenSSL support is available. This is not a complete TLS 1.3 handshake or a final-spec conformance test.
2. Construct the Alice and Bob key-share buffers from their classical and PQC components.
3. Check the expected combined key-share lengths and the resulting shared-secret lengths. The current source records only the two public-key decode statuses; key generation, key encoding, ECDH, encapsulation, decapsulation, and the final public-key decode return statuses are not checked.
4. Compare Alice's and Bob's combined shared-secret buffers byte-for-byte.
5. Treat unsupported-version results separately from a completed hybrid agreement.

### Procedure: OQS provider integration

1. At build time, `SUPPORT_OQS` selects the `pqc/oqs` test sources; otherwise dummy implementations are selected.
2. In an OQS-enabled build, ensure the provider can be loaded and the requested algorithm is available at runtime.
3. Run the selected OQS encoding, KEM or signature operation and inspect its explicit status/output checks.
4. Keep build-time source selection, provider/algorithm availability and successful cryptographic operation as separate conditions.

## 3. Evidence

### Source-level coverage

**1. Common ML-KEM path**

~~~text
OpenSSL >= 3.5?
  no  -> record not_supported
  yes -> for ML-KEM-512 / 768 / 1024:
           generate key pair -> check keygen status
           -> DER public-key encode/decode -> status checks
           -> RAW public-key encode/decode -> status checks
           -> assert EVP_PKEY_eq(DER-decoded, RAW-decoded)
           -> encapsulate -> status check
           -> decapsulate -> status check
           -> assert shared_secret_alice == shared_secret_bob
~~~

The KEM testcase compares the DER-decoded and RAW-decoded public-key objects through `EVP_PKEY_eq()` and compares both shared-secret buffers. Its assertion tests the return value as a boolean (nonzero), rather than requiring the documented equality result `1`; the test does not distinguish other nonzero return codes. Capsule and secret dumps are diagnostic, not expected-value assertions.

**2. PQC key encoding**

~~~text
PQC key object -> encode selected form -> decode
  -> status checks
  -> reconstructed-object equality only where explicitly asserted
~~~

Do not infer byte-for-byte canonical encoding from successful decode.

**3. Hybrid KEM**

~~~text
configured classical + PQC components
  -> compose hybrid KEM operation
  -> check operation statuses
  -> compare shared secrets only where source asserts equality
~~~

**4. OQS provider integration**

~~~text
SUPPORT_OQS enabled at build?
  no  -> dummy sources selected; no OQS algorithm proof
  yes -> compile oqs/ testcase sources
          -> runtime provider load + algorithm availability required
          -> execute selected OQS encode/KEM/signature path
~~~

A source file being compiled or a provider listing an algorithm is not itself a successful operation test. These are selected flow checks, not full conformance, malformed-key, cross-provider or interoperability suites.



**Source-to-case index**

| Source file | Focus | Explicit evidence / limitation |
|---|---|---|
| `testcase_pqc_dsa.cpp` | Common PQC signature placeholder | OpenSSL 3.5+ branch is `TODO`; older versions record `not_supported`; no sign/verify operation is implemented |
| `testcase_pqc_encode.cpp` | ML-KEM RAW private/public encoding | Status checks and private/public classification; no original-versus-decoded key equality assertion |
| `testcase_pqc_kem.cpp` | ML-KEM-512/768/1024 | OpenSSL 3.5+ guard; compares DER-decoded and RAW-decoded public keys with `EVP_PKEY_eq`, then compares encapsulated/decapsulated shared secrets |
| `testcase_pqc_hybrid_kem.cpp` | Draft X25519 + ML-KEM-768 hybrid key-share prototype | Checks component lengths and combined shared-secret equality; most keygen/encode/ECDH/KEM operation return values are ignored |
| `oqs/testcase_oqs_encode.cpp` | Enumerate OQS KEM/signature algorithms and try PEM/DER encoding variants for OID-registered entries | Enumeration or successful encoding alone does not prove an end-to-end algorithm operation |
| `oqs/testcase_oqs_kem.cpp` | OQS key generation, serialization, encapsulation and decapsulation | Compare sender/receiver shared secrets |
| `oqs/testcase_oqs_dsa.cpp` | OID-registered OQS signatures | Sign/verify operation path; inspect source assertions for the precise oracle |

```text
CMake SUPPORT_OQS
  ├─ disabled → dummy OQS testcase implementations
  └─ enabled  → oqs/ testcase sources
                  ├─ encode: enumerate + try supported PEM/DER forms
                  ├─ KEM: key → encode/decode → encapsulate/decapsulate
                  │        → compare shared secrets
                  └─ DSA: sign → verify
                           ↓
                 runtime provider and algorithm availability
```

The common ML-KEM and hybrid KEM paths are distinct from the provider-backed OQS paths. Build-time inclusion, runtime provider availability, and a successful cryptographic operation are separate conditions.

### Documentation and verification status

The current branch does not contain the referenced `test/testcase/crypto/report` file. No aggregate report is available here to substantiate a PQC/OQS result, and no tests were run during this documentation pass.

## 4. Relationships

- `oqs/` contains provider-specific tests.
- `sdk/crypto/oqs/` documents the provider adapter.
- `sdk/crypto/basic/` contains common cryptographic abstractions.
- Related testcase source: `testcase_pqc_dsa.cpp`, `testcase_pqc_encode.cpp`, `testcase_pqc_hybrid_kem.cpp`, `testcase_pqc_kem.cpp`, `oqs/testcase_oqs_encode.cpp`, `oqs/testcase_oqs_kem.cpp`, `oqs/testcase_oqs_dsa.cpp`



## 5. References

No external references are currently listed.
