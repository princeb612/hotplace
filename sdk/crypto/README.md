# Crypto

`sdk/crypto` contains hotplace's cryptographic primitives, key/signature abstractions, protocol-oriented cryptographic formats, and backend adapters.

The implementation is centered on OpenSSL-backed primitives, while higher layers adapt those primitives to protocol formats such as COSE, JOSE, and Windows Authenticode.

## Areas

### basic

The core cryptographic abstraction and primitive layer.

- `crypt.md` — encryption and AEAD processing
- `digest.md` — digest/hash processing
- `kdf.md` — key derivation functions
- `key.md` — key objects, import/export, generation, and exchange
- `mac.md` — MAC/HMAC/CMAC processing
- `sign.md` — digital signature processing
- `backend.md` — OpenSSL/provider-backed support, PRNG, and PQC integration

Existing study/reference documents remain alongside these module records, including cipher, digest/MAC, elliptic-curve, OID, and CBC-HMAC material.

### advisor

Cryptographic identifier and capability metadata used to connect hotplace identifiers with backend and protocol identifiers.

- `crypto_advisor.md`

### authenticode

Windows PE Authenticode verification support. This is focused on PE signature verification rather than a general digital-certificate framework.

- `authenticode_verifier.md`
- `authenticode-pe-plugin.md`

### cose

CBOR Object Signing and Encryption processing.

- `cose-message-model.md`
- `cose-cryptographic-processing.md`
- `cose-key-and-countersign.md`
- `cose-overview.md` — existing COSE study/reference material

### jose

JSON Object Signing and Encryption processing.

- `jose-object-model.md`
- `jose-signing-encryption.md`
- `jose-key-and-algorithms.md`
- `jose-overview.md` — existing JOSE study/reference material

### oqs

OpenSSL 3 provider integration for post-quantum cryptography. The hotplace layer is an adapter around provider-discovered KEM/signature algorithms rather than an implementation of the PQC algorithms themselves.

- `oqs-provider-adapter.md`
- `oqs-tests.md`
- `oqs-overview.md` — existing OQS study/reference material

## Relationship

```text
                         sdk/crypto
                              |
          +-------------------+-------------------+
          |                   |                   |
        basic               advisor          protocol formats
          |                   |             /       |       \
    OpenSSL crypto       identifiers      JOSE     COSE   Authenticode
          |                   |             |        |        |
          +-------------------+-------------+--------+--------+
                              |
                         crypto objects
                              |
                     backend/provider layer
                              |
                         OpenSSL / OQS
```

`basic` is the primitive and object layer. `advisor` supplies identifier/capability mapping. JOSE, COSE, and Authenticode consume those facilities for protocol-specific processing. `oqs` extends the backend side through an OpenSSL 3 provider.

## Related areas

- `sdk/io/cbor/` — CBOR object and encoding layer used by COSE
- `sdk/io/json/` — JSON processing used by JOSE-related paths
- `sdk/io/string/` — URL/string helpers used by protocol-oriented crypto code
- `sdk/base/encoding/` — binary/base encoding facilities
- `sdk/net/` — TLS/HTTP and protocol consumers

## Tests

Crypto tests are primarily under `test/testcase/crypto/`, with additional protocol-specific tests under their corresponding testcase directories.

The tests cover primitive operations, key/signature processing, protocol test vectors, and backend/provider integration.

## References

### RFC

- RFC 2104 — HMAC
- RFC 3394 / RFC 5649 — AES Key Wrap
- RFC 4226 / RFC 6238 — HOTP / TOTP
- RFC 4493 — AES-CMAC
- RFC 6070 / RFC 7914 / RFC 9106 — PBKDF2 / scrypt / Argon2
- RFC 7515 / RFC 7516 / RFC 7517 / RFC 7518 — JWS / JWE / JWK / JWA
- RFC 7520 — JOSE examples
- RFC 8037 — ECDH and signatures for JOSE
- RFC 8152 — COSE
- RFC 8017 — PKCS #1

### Online resources

Existing reference links include IANA JOSE/COSE/TLS registries, OpenSSL documentation, COSE examples, OID databases, and standard curve databases. Detailed links remain in the corresponding study/reference documents.
