# Cryptographic Primitives

`crypto/basic` contains the low-level cryptographic primitives used by higher-level modules such as TLS, JOSE, COSE, and Authenticode. The implementation is largely built around the OpenSSL backend and is organized around encryption, digest/MAC, key handling, KDF, signature, PRNG, and PQC support.

This directory is the implementation layer; protocol-specific use belongs in the higher-level modules.

## Topics

- [Cipher](cipher.md) — supported cipher families, modes, and tested algorithms
- [Digest and MAC](digest-and-mac.md) — digest/HMAC/CMAC test coverage and size references
- [KDF](kdf.md) — KDF overview and references
- [Elliptic Curves](elliptic-curves.md) — curve classification and notation notes
- [OID](oid.md) — OID references and examples
- [CBC-HMAC survey](mac/cbc-hmac-survey.md) — CBC-HMAC / MtE / EtM study material

## Implementation areas

- [`crypt/`](crypt/README.md) — encryption and AEAD primitives
- [`digest/`](digest/README.md) — digest and transcript-hash implementation
- [`kdf/`](kdf/README.md) — key derivation functions
- [`key/`](key/README.md) — key objects, key chains, key generation, and key exchange
- [`mac/`](mac/README.md) — HMAC, CBC-HMAC, and OTP-related implementation
- [`sign/`](sign/README.md) — digital signatures
- `prng/` — pseudo-random number generation
- `pqc/` — post-quantum cryptographic support
- `sdk/` — OpenSSL SDK/backend support

## Verification

The corresponding crypto testcases are collected under [`test/testcase/crypto`](../../../test/testcase/crypto/README.md). They cover encryption, hashes, KDFs, keys/key exchange, signatures, PRNG, and PQC, including RFC and test-vector based cases.

- [`test/testcase/crypto/crypt/`](../../../test/testcase/crypto/crypt/README.md)
- [`test/testcase/crypto/hash/`](../../../test/testcase/crypto/hash/README.md)
- [`test/testcase/crypto/kdf/`](../../../test/testcase/crypto/kdf/README.md)
- [`test/testcase/crypto/key/`](../../../test/testcase/crypto/key/README.md)
- [`test/testcase/crypto/sign/`](../../../test/testcase/crypto/sign/README.md)
- [`test/testcase/crypto/pqc/`](../../../test/testcase/crypto/pqc/README.md)
- [`test/testcase/crypto/prng/`](../../../test/testcase/crypto/prng/README.md)

## Related

- [`sdk/crypto/README.md`](../README.md) — crypto subsystem overview
- [`sdk/crypto/advisor/README.md`](../advisor/README.md) — algorithm/parameter lookup
- [`sdk/net/tls/`](../../net/tls/README.md) — protocol use of crypto primitives
- [`sdk/io/asn.1/`](../../io/asn.1/README.md) — ASN.1/DER representation used by crypto code
