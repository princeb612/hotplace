## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1106                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Post-quantum cryptography testcase directory

## 1. What

This directory contains direct tests for hotplace's PQC abstractions and the optional OQS provider integration. It is a source map; it does not imply that all tests are enabled in every build.

## 2. How

### Procedure: common PQC signature operations

1. Resolve the supported PQC signature algorithm/key identifier for the active OpenSSL build.
2. Create or load the key, sign the test message, and pass the produced signature to the verification operation.
3. Record sign and verify statuses. The common DSA-style PQC test is an operation/round-trip path, not a fixed signature-byte known-answer vector.
4. Unsupported algorithms/providers are reported as unsupported, not as successful signature verification.

### Procedure: key encoding and decoding

1. Create or obtain a PQC key and select the supported public/private representation.
2. Encode the key, decode the resulting representation, and check each operation's status.
3. Compare the reconstructed key object where the source explicitly asserts equality. Successful decoding alone does not prove canonical encoding or full parameter preservation.

### Procedure: run the common ML-KEM path

1. The testcase runs ML-KEM-512, ML-KEM-768 and ML-KEM-1024 only under its OpenSSL 3.5-or-later guard.
2. Generate a key pair and check the operation status.
3. Encode/decode the public key through the supported DER form and raw form; compare reconstructed public-key objects where the source does so.
4. Encapsulate to obtain a ciphertext and sender shared secret, then decapsulate with the private key to obtain the receiver shared secret.
5. Compare the two shared-secret buffers. Logged ciphertexts/secrets are diagnostic, not fixed known-answer values.

### Procedure: hybrid ECDHE-ML-KEM key agreement

1. Run the composed classical X25519 and ML-KEM-768 key-agreement flow when the required OpenSSL support is available.
2. Construct the Alice and Bob key-share buffers from their classical and PQC components.
3. Check the expected combined key-share lengths and the resulting shared-secret lengths.
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

The test compares decoded public-key objects and both shared secrets. Capsule and secret dumps are diagnostic, not expected-value assertions.

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


### Documentation and verification status

No tests were run during this documentation pass. The supplied aggregate crypto report does not isolate the PQC/OQS directory, so no per-directory result is asserted here.

## 4. Relationships

- [PQC testcase detail map](testcase_pqc.md)
- `oqs/` contains provider-specific tests.
- `sdk/crypto/oqs/` documents the provider adapter.
- `sdk/crypto/basic/` contains common cryptographic abstractions.

## 5. References

- `testcase_pqc_dsa.cpp`
- `testcase_pqc_encode.cpp`
- `testcase_pqc_hybrid_kem.cpp`
- `testcase_pqc_kem.cpp`
- `oqs/testcase_oqs_encode.cpp`
- `oqs/testcase_oqs_kem.cpp`
- `oqs/testcase_oqs_dsa.cpp`
