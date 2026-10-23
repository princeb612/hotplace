## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Cryptographic Primitives

## 1. Role

`crypto/basic` is the reusable cryptographic operation and key-material layer used by higher-level modules such as TLS, JOSE, COSE, and Authenticode. The implementation is largely built around OpenSSL and includes generic interfaces/builders alongside backend-specific implementations.

This layer supplies operations and key abstractions. It does not decide the full sequencing of a TLS handshake, the JSON/CBOR serialization of JOSE/COSE messages, or the trust policy of Authenticode verification.

## 2. Data Model

This directory is a **module map**, not a single runtime data model. Each child owns its concrete objects and state; the table below identifies those models and the data each one carries.

| Module | Main data model | Data that matters to the caller |
|---|---|---|
| [`crypt/`](crypt/README.md) | Cipher contexts, operation facades and builders | Algorithm/mode or scheme, key, IV/nonce, AAD and authentication tag |
| [`digest/`](digest/README.md) | Digest objects and transcript-hash state | Selected hash algorithm, accumulated byte sequence and checkpoint state |
| [`kdf/`](kdf/README.md) | Algorithm-specific derivation inputs | IKM/password, salt, context/info, cost parameters and requested output length |
| [`key/`](key/README.md) | Key objects, metadata and collections | Key material, `kid`, algorithm/use/group metadata, family-specific parameters and ownership |
| [`mac/`](mac/README.md) | Keyed MAC objects and OTP parameters | Secret key, hash/MAC choice, counter or time-step, digit count and construction-specific byte layout |
| [`sign/`](sign/README.md) | Signature operation configuration | Signature scheme/category, digest, key type, PSS parameters and message/signature bytes |
| [`backend.md`](backend.md) | OpenSSL SDK, PRNG and PQC integration | Startup reference counts, random-byte/encoded-string outputs, key encoding, KEM capsule/shared-secret and signature data |

The source tree also contains pseudo-random generation, post-quantum operation support and OpenSSL SDK/backend support. These are directory responsibilities rather than fields in one shared object; consult [`backend.md`](backend.md) and its source entry points for the concrete state and interfaces.

The interfaces/builders separate caller-facing operation contracts from concrete OpenSSL implementations. The key layer provides common key representation and family-specific construction; higher-level formats and protocols supply their own identifiers, message structures and operation timing.

## 3. Behavior Model

### 3.1 Common primitive-selection path

The child modules use different public APIs, but many follow the same broad route from a caller's intent to a concrete operation:

```text
protocol/application intent
  (algorithm ID, name, parameters, key material)
                   |
                   v
        advisor / input decoding
                   |
                   v
          builder or key facade
                   |
                   v
      operation-specific data model
                   |
                   v
       OpenSSL/backend operation
                   |
                   v
       bytes, status, or verification result
```

This is a navigation model, not a claim that every child uses every stage. For example, `crypto_keygen` decodes named key parameters before family-specific construction; a one-shot digest may need only algorithm selection and a backend context; a TLS label helper serializes protocol-defined inputs before calling HKDF.

### 3.2 Cross-cutting behavior boundaries

- **Algorithm resolution is not backend availability.** Advisor metadata maps names and protocol identifiers to internal categories or methods. The selected OpenSSL version, provider and key parameters still determine whether the operation can execute.
- **Data representation is not operation policy.** A key object may carry a public key, private key or certificate, but the caller/protocol determines whether that material is suitable and which representation should be exported.
- **Primitive output is not protocol completion.** Digest/MAC/signature bytes, a shared secret or KDF output are inputs to higher-level state machines. TLS, JOSE and COSE remain responsible for their message formats, ordering and protocol-specific validation.
- **Ownership follows the concrete API.** OpenSSL reference counts, borrowed pointers, byte-buffer lifetimes and builder reuse rules are defined by each child module; they should not be inferred from the common facade alone.

## 4. Relationships
- [`sdk/crypto/README.md`](../README.md) — crypto subsystem overview and backend boundaries.
- [`sdk/crypto/advisor/README.md`](../advisor/README.md) — algorithm and parameter lookup.
- [`sdk/net/tls/`](../../net/tls/README.md) — protocol use of crypto primitives and transcript hashing.
- [`sdk/io/asn.1/`](../../io/asn.1/README.md) — ASN.1/DER representation used by crypto-related paths.
- [`test/testcase/crypto/`](../../../test/testcase/crypto/README.md) — source testcase organization.

### Implementation and source entry points

The module READMEs link to the relevant source and testcase entry points for each primitive family. Testcase references describe source-level coverage and must not be read as proof that the tests ran in a particular environment.

## 5. References
- [OpenSSL EVP overview](https://docs.openssl.org/3.0/man7/evp/) — common high-level interfaces for cryptographic operations.
- [OpenSSL EVP_PKEY](https://docs.openssl.org/3.0/man7/EVP_PKEY/) — public-key objects and key-operation interfaces.
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869) — HKDF construction and its extract/expand stages.
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446) — transcript hashes, key schedule, and TLS key-share use.
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032) — Ed25519 and Ed448 signature schemes.
- [RFC 7748: Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748) — X25519 and X448 key agreement.

## 7. Developer Notes

These notes preserve cross-directory inventories, reference examples, and study material that do not belong to one implementation directory's README. They are intentionally not presented as complete API specifications or universal support claims.

### 6.1 Cipher inventory

The inventory below records combinations represented in the source-maintained table. It does not guarantee availability in every OpenSSL build/provider.

| Algorithm | CBC | CFB | CFB1 | CFB8 | CTR | ECB | GCM | OFB | Key wrap |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| AES | O | O | O | O | O | O | O | O | O |
| ARIA | O | O | O | O | O | O | O | O | |
| BF | O | O | | | | O | | O | |
| CAMELLIA | O | O | O | O | O | O | | O | |
| CAST | O | O | | | | O | | O | |
| DES | O | O | | | | O | | O | |
| IDEA | O | O | | | | O | | O | |
| RC2 | O | O | | | | O | | O | |
| RC5 | O | O | | | | O | | O | |
| SEED | O | O | | | | O | | O | |
| SM4 | O | O | | | | O | | O | |

Source-maintained key/IV-size examples (bytes):

| Algorithm | Key | IV |
|---|---:|---:|
| AES-128 | 16 | 16 |
| AES-192 | 24 | 16 |
| AES-256 | 32 | 16 |
| Blowfish | 16 | 8 |
| ARIA-128 | 16 | 16 |
| ARIA-192 | 24 | 16 |
| ARIA-256 | 32 | 16 |
| Camellia-128 | 16 | 16 |
| Camellia-192 | 24 | 16 |
| Camellia-256 | 32 | 16 |
| ChaCha20 | 32 | 12 |

Mode and parameter requirements are algorithm-specific; this table is an orientation aid, not a substitute for the operation's contract. See [`crypt/README.md`](crypt/README.md) for symmetric, AEAD and public-key encryption boundaries.

### 6.2 Digest, HMAC and CMAC inventory

Digest output lengths and the source-maintained HMAC combinations are listed here for quick comparison. Provider support may differ by build; SHAKE output length, for example, is caller-selected rather than a fixed digest size.

| Digest | Bits | Bytes |
|---|---:|---:|
| MD5 | 128 | 16 |
| SHA-1 | 160 | 20 |
| SHA-224 | 224 | 28 |
| SHA-256 | 256 | 32 |
| SHA-384 | 384 | 48 |
| SHA-512 | 512 | 64 |
| SHA-512/224 | 224 | 28 |
| SHA-512/256 | 256 | 32 |
| SHA3-224 | 224 | 28 |
| SHA3-256 | 256 | 32 |
| SHA3-384 | 384 | 48 |
| SHA3-512 | 512 | 64 |

| Algorithm | Digest listed | HMAC listed |
|---|---:|---:|
| MD4 | O | O |
| MD5 | O | O |
| SHA-1 | O | O |
| SHA-224 | O | O |
| SHA-384 | O | O |
| SHA-512 | O | O |
| SHA3-224 | O | O |
| SHA3-256 | O | O |
| SHA3-384 | O | O |
| SHA3-512 | O | O |
| SHAKE128 | O | |
| SHAKE256 | O | |
| BLAKE2b-512 | O | O |
| BLAKE2s-256 | O | O |
| RIPEMD-160 | O | O |
| Whirlpool | O | O |

The original CMAC note identifies AES-CBC-MAC as a related source-tested construction. See [`digest/README.md`](digest/README.md) for digest/transcript behavior and [`mac/README.md`](mac/README.md) for HMAC, CMAC, CBC-HMAC and OTP semantics.

### 6.3 Elliptic-curve taxonomy

This classification is a conceptual map, not a statement that every named curve is supported by every backend or platform.

- **Finite field**
  - Prime field (𝔽p): short-Weierstrass curves such as P-256, P-384 and P-521, commonly represented by (y^2 = x^3 + ax + b pmod p).
  - Binary field (𝔽2^m): historical binary curves such as B-163, B-233, B-283, K-163 and K-233, with forms such as (y^2 + xy = x^3 + ax^2 + b).
- **Curve form**
  - Weierstrass: (y^2 = x^3 + ax + b).
  - Edwards: (x^2 + y^2 = 1 + d x^2 y^2); Ed25519 and Ed448 are signature algorithms in this family.
  - Montgomery: (By^2 = x^3 + Ax^2 + x); X25519 and X448 use this form for key agreement.
- **Special family**
  - Koblitz curves, including examples such as K-163 and K-233.

The mathematical curve form, the cryptographic operation, the wire/key representation and provider availability are distinct dimensions. X25519/X448 and Ed25519/Ed448 are not interchangeable simply because their constructions are related. The implementation-facing curve and alias lookup is in [`advisor/README.md`](../advisor/README.md); key construction and exchange are in [`key/README.md`](key/README.md).

### 6.4 Object Identifiers (OID) examples

OIDs identify algorithm or parameter arcs; they are not operations and do not prove backend support. The following are preserved as reference examples; validate aliases against the actual advisor/resource tables before relying on them.

| Example | Dotted OID | Meaning noted in the original reference |
|---|---|---|
| prime256v1 / secp256r1 | `1.2.840.10045.3.1.7` | ANSI X9.62 prime curve |
| secp112r1 | `1.3.132.0.6` | Certicom curve |
| brainpoolP160r1 | `1.3.36.3.3.2.8.1.1.1` | TeleTrusT curve |
| X25519 | `1.3.101.110` | X25519 algorithm identifier |

An OID can be rendered as a dotted string, ASN.1 name/value sequence, OID-IRI or `urn:oid:` form. For example, `1.3.101.110` may be written as `urn:oid:1.3.101.110`. External lookup aid: [OID Repository](https://oid-base.com/).

In hotplace, OIDs, OpenSSL NIDs and protocol-specific identifiers meet at different lookup/conversion boundaries. See [`sdk/io/basic/oid.md`](../../io/basic/oid.md) for generic OID conversion and [`advisor/README.md`](../advisor/README.md) for crypto-specific metadata. The original examples included RFC 3279 as a general algorithm-identifier reference.

### 6.5 CBC-HMAC study note

[`mac/cbc-hmac-survey.md`](mac/cbc-hmac-survey.md) remains a separate developer note because it compares construction-specific input layouts: TLS MAC-then-encrypt (MtE), TLS encrypt-then-MAC (EtM), and JOSE AES-CBC-HMAC. It is useful for understanding protocol differences, but should not be treated as a generic recipe for designing a new authenticated-encryption scheme.
