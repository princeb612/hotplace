# Crypto Testcases

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
