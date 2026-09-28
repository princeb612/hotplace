# Cryptographic Primitives

`crypto/basic` contains the low-level cryptographic primitives used by higher-level modules such as TLS, JOSE, COSE, and Authenticode.  The implementation is largely built around the OpenSSL backend and is organized around encryption, digest/MAC, key handling, KDF, signature, PRNG, and PQC support.

This directory is the implementation layer; protocol-specific use belongs in the higher-level modules.

## Topics

- [Cipher](cipher.md)
  - Supported block/stream cipher modes and the currently tested algorithms
  - Block-cipher key/IV size reference
- [Digest and MAC](digest-and-mac.md)
  - Digest/HMAC/CMAC test coverage
  - Digest size reference
- [KDF](kdf.md)
  - HKDF, PBKDF2, scrypt, and Argon2
- [Elliptic Curves](elliptic-curves.md)
  - Curve classification and notation notes
- [OID](oid.md)
  - OID references and examples used while working with cryptographic algorithms and curves
- [MAC study](mac/cbc-hmac-survey.md)
  - CBC-HMAC / MtE / EtM study and verification material

## Implementation

The main implementation areas are:

- `crypt/` — encryption and AEAD
- `digest/` — digest and transcript-hash implementation
- `kdf/` — key derivation functions
- `key/` — key objects, key chains, key generation, and key exchange
- `mac/` — HMAC and CBC-HMAC
- `sign/` — digital signatures
- `prng/` — pseudo-random number generation
- `pqc/` — post-quantum cryptographic support
- `sdk/` — OpenSSL SDK/backend support

## Verification

The corresponding crypto testcases are collected under [`test/testcase/crypto`](../../../test/testcase/crypto/README.md).  They cover encryption, hashes, KDFs, keys/key exchange, signatures, PRNG, and PQC, including RFC and test-vector based cases.

## Related

- [`sdk/crypto/README.md`](../README.md) — crypto subsystem overview
- [`sdk/crypto/basic/mac/README.md`](mac/README.md) — MAC implementation area
- [`test/testcase/crypto/README.md`](../../../test/testcase/crypto/README.md) — crypto testcase area
