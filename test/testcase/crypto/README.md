## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Crypto Testcases

## 1. Role

This directory contains testcase entry points and focused testcase groups for hotplace's cryptographic primitives and selected integrations. The tests cover known-answer vectors, key and signature processing, key derivation, random-number facilities, and optional post-quantum/provider paths.

This README describes organization and source-level behavior. It does not claim every algorithm or backend is available in every build, nor that the tests have been executed for the revision named above.

## 2. Test model

### Entry point and testcase groups

`sample.cpp` configures command-line options, logging, and the testcase harness; starts OpenSSL integration with `openssl_startup()`; invokes registered testcase functions; and performs cleanup with `openssl_cleanup()` before reporting the result.

- `crypt/` — ciphers, block ciphers, AEAD, and related known-answer vectors.
- `hash/` — hashes, HMAC/CMAC, transcript-hash, and related checks.
- `kdf/` — HKDF and other key-derivation functions.
- `key/` — key generation and formats, curves, DH/EC, HPKE, and key exchange.
- `sign/` — signature algorithms and signature vectors.
- `prng/` — random and pseudo-random generation tests.
- `pqc/` — post-quantum and OQS/provider-related tests.

Some test paths are conditional. For example, `sample.cpp` enables slower PBKDF2/scrypt cases only with `-s`, Argon2 cases only with `-argon2`, and FFDHE cases only with `-ffdhe`. OQS/PQC behavior also depends on build configuration and the installed provider/backend. A function's presence in the source does not prove that an optional path ran in a particular report.

### Test data

Inputs may be declared directly in C++ or loaded from structured YAML vectors. The vector schema and algorithm-specific references remain in separate topic documents to avoid duplicating them here.

## 3. Example: test vector to cryptographic assertion

`test/testcase/crypto/kdf/testcase_hkdf.cpp` gives a compact known-answer example. The test starts the `hkdf` testcase group, creates an `openssl_kdf`, and defines a vector using password `secret`, salt `salt`, info `label`, SHA-256, and an output length of 10 bytes. It calls `hmac_kdf`, converts the inputs to the library's binary representation, and compares the derived output with the expected hexadecimal value `2ac4369f525996f8de13`.

The assertion checks exact output bytes rather than merely a successful return code. It establishes behavior for that vector and code path; it does not prove every HKDF parameter combination, digest, provider, or other KDF is covered.

For other algorithms, follow the consuming C++ testcase to identify whether it checks exact bytes, a status/result, a round trip, or only diagnostic output.

## 4. Test and verification status

### 4.1 Source-level coverage

Coverage is defined by registered testcase functions, inputs, conditional guards, and assertions. The presence of an algorithm directory or a vector schema alone does not establish that its vectors are loaded or that both success and failure cases are checked.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../test-report-status.md) associates the last known run with **Revision 1104 · MinGW64/GCC · CTest** based on conversation context; the report itself does not identify the tested source revision, OS/compiler build details, or exact configuration. This is distinct from the current documentation basis, Revision 1105. Preserve the counts until a newer report set is supplied. No runtime tests were executed as part of this documentation update.

## 5. Relationships

- [Crypto implementation overview](../../../sdk/crypto/README.md) — module boundaries and backend/provider configuration.
- [Basic cryptographic primitives](../../../sdk/crypto/basic/README.md) — cipher, digest, KDF, key, MAC, and signature implementations.
- `test/testcase/cose/` and `test/testcase/jose/` — format-specific crypto consumers, distinct from primitive known-answer tests.
- `test/testcase/tls/` — TLS-specific transcript, key-schedule, and record-protection tests.

## 6. References

- [Test vectors and external references](test-vectors.md)
- [ECDSA curve/hash reference](ecdsa-curves.md)
- [Post-quantum cryptography](pqc.md)
- [oqs-provider](oqs-provider.md)
- [Test-vector YAML schemas](testvector-schema.md)
- `test/testcase/crypto/sample.cpp`
- `test/testcase/crypto/kdf/testcase_hkdf.cpp`
