## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Crypto Testcases

## 1. Role

This document records testcase organization, test-vector schema, or reference material for the crypto test area. Its presence does not by itself establish runtime verification.

## 2. Test model

This directory contains crypto testcases and test-vector based verification for the cryptographic components in `sdk/crypto`.

The detailed reference material is separated by purpose so this README can remain the directory-level entry point.

## Test sources


- `crypt/` — cipher, AEAD and related test vectors
- `hash/` — hash, HMAC/CMAC and transcript-hash tests
- `kdf/` — KDF and RFC test vectors
- `key/` — key generation, key formats, curves, DH/EC and HPKE
- `sign/` — signature algorithms and signature test vectors
- `prng/` — random/PRNG tests
- `pqc/` — post-quantum cryptography and OQS tests


## Reference material


- [Test vectors and external references](test-vectors.md)
- [ECDSA curve/hash reference](ecdsa-curves.md)
- [Post-quantum cryptography](pqc.md)
- [oqs-provider](oqs-provider.md)
- [Test-vector YAML schemas](testvector-schema.md)


## Related


- [Crypto implementation](../../../sdk/crypto/README.md)
- [Basic cryptographic primitives](../../../sdk/crypto/basic/README.md)

The topic documents above retain the study, reference, and schema material that previously lived in this README.

## 3. Example: Source inventory and test-vector use

The retained material is a schema/reference or directory-level record. Consult the listed testcase source files to determine which functions consume these inputs and what assertions they make.

## 4. Test and verification status

### 4.1 Source-level coverage

No claim of algorithmic coverage is inferred from this reference document alone. Coverage must be established from the consuming C++ testcase functions and their expected-result checks.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Crypto implementation: `sdk/crypto/README.md`
- Test sources and vector consumers are located in the corresponding sibling testcase directories.

## 6. References

Source files in this directory:
- `test/testcase/crypto/sample.cpp`
