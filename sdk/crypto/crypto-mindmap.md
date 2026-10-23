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
# Crypto Mindmap

## 1. Role

This mindmap is a navigation aid for the cryptographic subsystem: primitive operations and key objects are grouped under `basic`, metadata lookup under `advisor`, and protocol/format integrations under COSE, JOSE, OQS, and Authenticode. The diagram summarizes topic relationships, not a class inheritance graph or a guarantee that every listed algorithm is enabled.

## 2. Data Model

The map below is a source-tree taxonomy. It groups related concepts but does not imply that every leaf is implemented, enabled, or exercised by every build.

    crypto
    ├── basic
    │   ├── crypt
    │   │   └── AEAD: AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CBC-HMAC-SHA
    │   ├── digest: hash, transcript hash
    │   ├── mac: HMAC, CMAC, OTP
    │   ├── sign: DSA, ECDSA, EdDSA, ML-DSA, RSA
    │   ├── key: DH, DSA, EC, OKP, RSA
    │   ├── key exchange: ECDH, KEM, hybrid KEM
    │   ├── KDF: HKDF, PBKDF2, scrypt, Argon2, TLS/DTLS labels
    │   ├── PQC
    │   └── PRNG
    ├── advisor: identifiers, algorithm parameters, backend and protocol mappings
    ├── COSE: CBOR security-message formats
    ├── JOSE: JSON security-message formats
    ├── OQS: OpenSSL provider adapter for post-quantum operations
    └── Authenticode: Windows PE signature verification
## 3. Behavior Model

The major paths connect in different ways; they should not be collapsed into a universal crypto pipeline.

    protocol / format identifier
              │
              ▼
     crypto_advisor ──► hint metadata / identifier mapping
              │                          │
              ▼                          ▼
    basic operation or key abstraction  format-specific policy
              │                          │
              ├─ cipher / digest / KDF   ├─ JOSE JWS/JWE/JWK
              ├─ MAC / signature         ├─ COSE Sign/Mac/Encrypt
              └─ key generation/exchange └─ Authenticode PE verification

    OQS-enabled build
        └─ isolated OpenSSL library context
              └─ default + OQS provider
                    └─ provider-backed KEM/signature operations

- **basic** performs or adapts primitive operations and key-material handling.
- **advisor** maps identifiers and describes algorithms/parameters; a matching hint does not guarantee an executable backend method.
- **JOSE and COSE** construct format-defined signing inputs, authenticated structures, recipient/key-management layers, and serialized message objects around the primitives.
- **OQS** delegates to algorithms exposed by a separately available provider; build flags and runtime provider configuration determine whether that path is usable.
- **Authenticode** follows the PE-specific image-digest and signed-content verification path, then performs signer/certificate checks. It is not a general-purpose certificate-policy framework.

These paths illustrate module boundaries, not complete conformance or runtime test results.
## 4. Relationships
### Module relationships

### Source-test evidence

Representative source paths include `test/testcase/crypto/crypt/` for ciphers/AEAD, `test/testcase/crypto/hash/` for digests/MAC/transcript hashes, `test/testcase/crypto/key/` for key objects/generation/exchange, `test/testcase/crypto/sign/` for signatures, and the COSE/JOSE testcase directories for format-level processing. Their presence identifies source coverage only; this documentation update did not execute them.

- [`basic/`](basic/README.md) — primitive operations, key objects, KDF, digest/MAC and signatures
- [`advisor/`](advisor/README.md) — metadata and identifier lookup
- [`cose/`](cose/README.md) and [`jose/`](jose/README.md) — format-specific message processing
- [`oqs/`](oqs/README.md) — post-quantum provider adapter
- [`authenticode/`](authenticode/README.md) — Windows PE Authenticode verification
