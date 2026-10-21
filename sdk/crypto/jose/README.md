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

# JOSE — JSON Object Signing and Encryption

## 1. Role

`sdk/crypto/jose` implements JSON-oriented JOSE message processing: JWS signatures/MACs, JWE encryption and key management, JWK key representation, and JWA/JWE algorithm identifiers. It composes security objects over `sdk/crypto/basic`; it does not reimplement RSA, ECDSA, HMAC, AES or key storage.

An important boundary: **JOSE is not the same thing as JWT.** JWT commonly uses JWS or JWE as its protection format, but JWT claims semantics and application policy are a layer above these generic JOSE operations.

## 2. Data Model

| Type | Responsibility |
|---|---|
| `json_object_signing` | JWS signing and verification; constructs the JOSE signing input and serialization. |
| `json_object_encryption` | JWE key management and content encryption/decryption. It keeps per-recipient key-management results separate from the shared content-encryption result. |
| `json_object_signing_encryption` | Combined public API and shared context lifecycle for signing, verification, encryption and decryption. |
| `json_web_key` | JWK JSON parsing/writing and conversion to/from the common `crypto_key` abstraction. |
| `json_web_signature` | JWS-oriented signing/verification helper. |
| `jose_context_t`, `jose_sign_t`, `jose_encryption_t`, `jose_recipient_t` | In-memory context, signature entries, content-encryption state and per-recipient key-management state. |
| `crypto_advisor` JOSE hints | Map JWS/JWA/JWE names to hotplace identifiers, key types and underlying primitive parameters. |

### JWS and JWE are different flows

```text
JWS:
protected header + payload
        ↓ JOSE signing input
crypto/basic signature or HMAC
        ↓
signature + compact / flattened JSON / general JSON serialization

JWE:
payload ──► content-encryption key (CEK) ──► AES-CBC-HMAC or AES-GCM
                  ▲                                │
                  │                                ▼
       per-recipient key management         ciphertext + tag + IV
       (RSA, ECDH-ES, AES-KW, PBES2...)      shared across recipients
```

JWS's `alg` selects a signature/MAC algorithm. JWE's `alg` selects key management, while `enc` selects content encryption. Confusing these two parameters leads to a wrong understanding of the implementation.

## 3. Behavior Model

### Algorithm inventory from the current resource tables

The lists below distinguish **metadata/enum mapping** from proven runtime availability. The resource tables in `resource_sign.cpp`, `resource_jose_algorithm.cpp` and `resource_jose_encryption.cpp` show what hotplace knows how to map; source testcases show which flows are exercised. The active OpenSSL/provider build and key type still determine whether a particular operation succeeds.

| JOSE role | Mapped algorithm families |
|---|---|
| JWS HMAC | HS256, HS384, HS512 |
| JWS RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| JWS RSA-PSS | PS256, PS384, PS512 |
| JWS ECDSA | ES256, ES384, ES512 |
| JWS Edwards signatures | EdDSA |
| Additional signature metadata | RS1 and ES256K appear in the shared signature resource table but have `jws_t::unknown`; they should not be presented as ordinary mapped JWS enum values. ML-DSA-44/65/87 have JWS enum entries and a guarded AKP testcase; current interoperability/registry status is separate from source-level implementation. SLH-DSA variants are present in the shared signature metadata but have `jws_t::unknown`, so that metadata alone does not establish JOSE JWS support. |
| JWE key management (`alg`) | RSA1_5, RSA-OAEP, RSA-OAEP-256; A128KW/A192KW/A256KW; dir; ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW; A128GCMKW/A192GCMKW/A256GCMKW; PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW |
| JWE content encryption (`enc`) | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512; A128GCM, A192GCM, A256GCM |
| JWK key types in the legacy status table | `oct`, RSA, EC (P-256/P-384/P-521), OKP (Ed25519, Ed448, X25519, X448); newer/provider-specific key families need their own source/test evidence. |

### Security-sensitive exclusions and legacy entries

The retained JOSE status note has a historical TODO item, “disable RSA1_5”. In the current source resource table, `RSA1_5` is still mapped as a JWA key-management algorithm, and the old status table marks it implemented. The documentation does not claim that it has been disabled: **metadata presence is not a security policy**. Applications should not interpret the mapping as a recommendation to use RSA1_5 for new designs.

Likewise, an algorithm absent from the mapped enum or testcase arrays should be described as “not mapped/tested in this source path,” not automatically as a deliberate security exclusion. Where the code explicitly marks an algorithm unavailable, that can be stated; where only an old TODO exists, it remains a maintainer note until the code confirms the policy.

### How JWT is handled

There is no separate JWT claims-processing API in this module's public model. The JOSE classes accept payload data and protect it using JWS or JWE:

- A **signed JWT** is typically a JWT claims JSON payload protected as a JWS. The JOSE layer can construct/verify the JWS envelope.
- An **encrypted JWT** is typically a JWT claims payload protected as a JWE. The JOSE layer can encrypt/decrypt the payload.
- Nested JWT constructions combine these envelopes at the application/protocol level.

This layer does not, by itself, validate registered JWT claims such as issuer, audience, expiration or not-before, nor does it decide authorization policy. After JWS verification/JWE decryption, the caller must parse and validate claims under the application's rules. A valid signature alone does not mean a token is acceptable.

### Serialization and context lifetime

The context separates protected headers, signature entries, encryption parameters and per-recipient fields. The API manages context through `open`, `close` and context-clearing operations. Serialization can be compact, flattened JSON or general JSON depending on the operation/message shape. For multi-recipient JWE, recipient-specific wrapped/derived CEK material is not the same thing as the shared content-encryption output.

## 4. Relationships

- `../basic/` provides keys, signatures, HMAC, AEAD, KDF and encryption primitives.
- `../advisor/` provides JOSE name/enum/key-type and primitive-parameter mappings.
- `../cose/` provides analogous security-object processing over CBOR with COSE-specific identifiers and authenticated structures.
- JOSE uses JSON representations; `../cose/` uses `../../io/cbor/` for CBOR maps, arrays and byte strings.
- `../../../test/testcase/jose/` contains RFC examples, serialization tests, JWK cases and provider-gated additional-key tests.

### Focused implementation records

- [JOSE object model and context](jose-object-model.md) — in-memory context, recipient and signature state.
- [JWS signing and JWE encryption](jose-signing-encryption.md) — operation-specific signing input, key management, content encryption and serialization flows.
- [JWK and algorithm mapping](jose-key-and-algorithms.md) — conversion between JWK key material, JOSE identifiers and common crypto abstractions.
- [Legacy implementation-status note](jose-overview.md) — preserved historical matrix/TODO; not the authoritative current support statement.

### Source-test evidence

- `testcase_rfc7515.cpp` includes the RFC 7515 A.1 HS256 example and checks generated compact output, then exercises flattened/general JSON forms.
- `testcase_rfc7516.cpp` exercises JWE examples.
- `testcase_rfc7517.cpp` exercises JWK conversion.
- `testcase_rfc7518.cpp` exercises JWA examples including RSA-PSS and RSA-OAEP.
- `testcase_rfc7520.cpp` exercises JOSE signature/encryption examples and combinations.
- `testcase_rfc7638.cpp` covers JWK thumbprints.
- `testcase_rfc8037.cpp` covers OKP/ECDH and Edwards signature examples.
- `testcase_akp.cpp` exercises ML-DSA-44/65/87 behind an OpenSSL 3.5+ compile-time guard.

The source-test map is useful for selecting exact test functions, but this documentation pass did not rerun those tests.

### Implementation entry points

- `json_object_signing.hpp/.cpp`, `json_object_signing_composer.cpp`
- `json_object_encryption.hpp/.cpp`, `json_object_encryption_composer.cpp`
- `json_object_signing_encryption.hpp/.cpp`
- `json_web_key.hpp/.cpp`, `json_web_signature.hpp/.cpp`
- `../advisor/resource_sign.cpp`, `resource_jose_algorithm.cpp`, `resource_jose_encryption.cpp`

## 5. References

- RFC 7515 — JSON Web Signature (JWS).
- RFC 7516 — JSON Web Encryption (JWE).
- RFC 7517 — JSON Web Key (JWK).
- RFC 7518 — JSON Web Algorithms (JWA).
- RFC 7519 — JSON Web Token (JWT).
- RFC 7520 — Examples of Protecting Content Using JOSE.
- RFC 7638 — JSON Web Key (JWK) Thumbprint.
- RFC 8037 — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE.
- IANA JOSE registry — https://www.iana.org/assignments/jose/jose.xhtml
