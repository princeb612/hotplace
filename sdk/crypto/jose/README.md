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

JWS's 'alg' selects a signature/MAC algorithm. JWE's 'alg' selects key management, while 'enc' selects content encryption. Confusing these two parameters leads to a wrong understanding of the implementation.

### Intermediate data model

| Data | Representation / owner | Purpose |
|---|---|---|
| JWS protected header | 'jose_sign_t.header'; Base64url-encoded JSON protected header | Supplies 'alg' and other protected parameters; its encoded form is part of the signing input. |
| JWS signing input | Constructed by the signing composer from encoded protected header and payload | Exact bytes passed to the signature or MAC primitive; not the final compact/JSON envelope. |
| JWS signature | 'jose_sign_t.signature' | Base64url-encoded result of signing the signing input; one 'jose_sign_t' per signature entry. |
| JWE 'alg' | Per-recipient 'jose_recipient_t' metadata/header | Selects key management: direct use, wrapping, password-based derivation, RSA transport, or ECDH-ES derivation. |
| JWE 'enc' | Shared 'jose_encryption_t' content-encryption configuration | Selects the algorithm protecting plaintext with the CEK, such as AES-GCM or AES-CBC-HMAC. |
| CEK | Content-encryption state plus recipient key-management state | The key used by 'enc'. For multi-recipient JWE, the recipient result is per recipient while content ciphertext/tag are shared. |
| 'encrypted_key' | Per-recipient 'crypt_item_t::encryptedkey' | Carries the recipient-specific CEK transport/wrapping result; it is empty for modes such as direct CEK use. |
| IV, ciphertext, tag | JWE content-encryption data map | IV and ciphertext/tag belong to the shared content-encryption result. AES-CBC-HMAC also requires authentication; ciphertext alone is not sufficient for acceptance. |
| Recipient parameters | 'jose_recipient_t': 'kid', 'epk', 'apu', 'apv', 'p2s', 'p2c', key-wrap 'iv'/'tag' | Parameters used by the selected key-management algorithm; not all are present for every 'alg'. |
| JWK key material | 'json_web_key' mapped to 'crypto_key' / 'crypto_keychain' | Represents key-type-specific public/private or symmetric material, with optional 'kid', 'use', 'alg', and curve metadata. |
| Serialization choice | 'jose_serialization_t' | Chooses compact, flattened JSON or general JSON output where supported; controls envelope layout, not the cryptographic primitive. |

The data model separates shared content protection from per-recipient key management. It also separates JOSE string identifiers from the 'jws_t', 'jwa_t' and 'jwe_t' values used internally.

### Collection shape and state ownership

The concrete declarations in `types.hpp` add two important constraints to the conceptual model above:

| Member | Actual shape | Consequence for the operation flow |
|---|---|---|
| `jose_context_t::key` | Retained `crypto_key*` | `open()` increments the key reference; `close()` releases it. It is not an owned copy of the key material. |
| `jose_context_t::protected_header` | `binary_t` | Stores protected-header bytes for compact/flattened processing; it is distinct from the encoded header string used in the JWS signing input. |
| `jose_context_t::signs` | `std::list<jose_sign_t>` | Holds parsed or generated signature entries; general JWS can carry multiple entries. |
| `jose_context_t::encryptions` | `std::map<jwe_t, jose_encryption_t>` | Content-encryption state is keyed by the selected `enc` enum, rather than by recipient identity. |
| `jose_encryption_t::recipients` | `std::map<jwa_t, jose_recipient_t>` | Recipient state is keyed by key-management algorithm. This representation does not distinguish two separate recipients that use the same `jwa_t` within the same encryption state. |
| `jose_recipient_t::datamap` | `crypt_datamap_t` | Carries algorithm-dependent binary values such as `encryptedkey`, `iv`, `tag`, `apu`, `apv` and `p2s`; only the selected algorithm's parameters are meaningful for a given recipient. |
| `jose_recipient_t::variantmap` and `p2c` | Variant map and integer | Preserve non-binary algorithm parameters such as ephemeral-key and PBES2 iteration state alongside the binary data map. |

This is an implementation-level collection model, not a claim that JOSE's general JSON serialization is limited to one recipient per algorithm. The map key means the in-memory representation itself cannot preserve two distinct same-algorithm recipients as separate entries.

## 3. Behavior Model

### Shared operation and context flow

```text
open(context, key)
    └─ retain key reference and initialize jose_context_t
             │
     sign / verify / encrypt / decrypt
             │
     resolve JOSE names or enum identifiers
             │
     focused operation class
       ├─ json_object_signing
       └─ json_object_encryption
             │
     build or parse JOSE message state
             │
     crypto/basic primitive + crypto/advisor metadata
             │
     compose / parse compact or JSON serialization
             │
     return status and operation result
             │
     clear transient context state
```

The combined API is a dispatcher, not the implementation of every operation. String-based entry points resolve JOSE names through advisor metadata and return an invalid-parameter error when the required mapping is absent. The focused classes own the signing or encryption flow. Their operation paths clear transient context state on exit, so callers should not assume the input/output message state remains populated for reuse after a completed call.

### JWS signing flow

```text
input payload + requested JWS alg/header(s)
                  │
          resolve jws_t / header claims
                  │
      build JOSE protected-header JSON
                  │
     Base64url(protected header) + "." + Base64url(payload)
                  │
            signing input bytes
                  │
     dosign(key, jws_t, signing input)
                  │
      crypto_sign_builder / HMAC primitive
                  │
        Base64url(signature bytes)
                  │
 composer emits compact / flattened / general JSON
```

For verification, the composer parses the received serialization into protected header, payload, signature and optional key identifier. The implementation reconstructs the signing input and invokes the matching verification operation. For multiple signatures, each signature entry is evaluated separately and the aggregate result is successful only when the required per-signature results succeed. Parsing a well-formed JOSE object is not itself proof of a valid signature.

### JWE encryption flow

```text
input plaintext + enc + recipient alg list
                  │
     resolve jwe_t (enc) and jwa_t (alg)
                  │
   prepare shared content-encryption state
   ├─ CEK
   ├─ IV
   └─ optional compression before encryption
                  │
   prepare each recipient independently
   ├─ resolve key / kid and algorithm parameters
   ├─ RSA transport, AES-KW/GCM-KW, PBES2,
   │  ECDH-ES or direct-key path
   └─ produce per-recipient encrypted_key
                  │
      encrypt plaintext once with CEK + enc
                  │
       ciphertext + tag + IV (shared result)
                  │
       composer emits compact / flattened /
                 general JSON
```

The recipient algorithm (`alg`) determines how a recipient obtains the CEK; the content-encryption algorithm (`enc`) determines how the payload is protected. For multi-recipient JWE, recipient-specific key-management output is attached to each recipient while the content ciphertext, IV and tag are shared. Direct-key and ECDH-ES direct modes do not follow the ordinary encrypted-key wrapping path.

The overload taking one `jwa_t` runs one selected key-management path, including the direct (`dir`) path. The overload taking a list is a different API path: it removes `dir` and `RSA1_5` from that list before processing the remaining algorithms. Therefore the existence of an enum/resource mapping does not mean that every overload accepts the same algorithm set. The list is also materialized into the `jose_encryption_t::recipients` map keyed by `jwa_t`, so duplicate entries for one algorithm do not represent distinct recipients.

**Observed implementation limits:** the list overload's composer and encryption calls return status values, but the final `compose_encryption()` status is not assigned to the function's return value. The current path can therefore return success even if serialization fails. Also, the in-memory recipient map is keyed only by algorithm, so two distinct recipients using the same `alg` cannot be retained independently. These are implementation constraints, not properties of the JWE format.

### JWE decryption flow

```text
serialized JWE
    └─ composer parses protected header, recipients,
       encrypted_key, IV, ciphertext and tag
             │
       resolve enc + candidate recipient alg/kid
             │
       recover / derive CEK for candidate recipient
             │
       authenticate and decrypt with enc
             │
       if configured: decompress plaintext
             │
       expose plaintext and boolean result
```

The decryption implementation parses the serialized message into shared content-encryption state and recipient-specific key-management state, then calls `dodecrypt()` for each recipient entry. The latter resolves a candidate key by recipient-level `kid`, falling back to the shared `kid`, and recovers/derives the CEK before authenticating and decrypting the shared ciphertext. With AES-CBC-HMAC, the MAC check is part of acceptance; with AEAD content encryption, tag verification is part of the decrypt operation. When the parsed `zip` parameter is `DEF`, decompression follows successful content decryption.

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

The historical JOSE maintenance notes included a TODO to “disable RSA1_5”. In the current source resource table, `RSA1_5` is still mapped as a JWA key-management algorithm, and the old status table marks it implemented. The documentation does not claim that it has been disabled: **metadata presence is not a security policy**. Applications should not interpret the mapping as a recommendation to use RSA1_5 for new designs.

Likewise, an algorithm absent from the mapped enum or testcase arrays should be described as “not mapped/tested in this source path,” not automatically as a deliberate security exclusion. Where the code explicitly marks an algorithm unavailable, that can be stated; where only a historical TODO exists, it remains a maintenance question until the code and intended policy are reconciled.

### How JWT is handled

There is no separate JWT claims-processing API in this module's public model. The JOSE classes accept payload data and protect it using JWS or JWE:

- A **signed JWT** is typically a JWT claims JSON payload protected as a JWS. The JOSE layer can construct/verify the JWS envelope.
- An **encrypted JWT** is typically a JWT claims payload protected as a JWE. The JOSE layer can encrypt/decrypt the payload.
- Nested JWT constructions combine these envelopes at the application/protocol level.

This layer does not, by itself, validate registered JWT claims such as issuer, audience, expiration or not-before, nor does it decide authorization policy. After JWS verification/JWE decryption, the caller must parse and validate claims under the application's rules. A valid signature alone does not mean a token is acceptable.

### Shared context lifecycle

```text
open(&context, key)
    ├─ allocate jose_context_t
    ├─ retain the crypto_key reference
    └─ initialize context flags and message state
             │
             ├─ sign / verify → jose_sign_t entries
             └─ encrypt / decrypt → jose_encryption_t + recipients
             │
       operation builds or parses message state
             │
       operation clears transient context data
             │
close(context) → release retained key and context
```

The API manages context through 'open', 'close' and context-clearing operations. The public wrapper dispatches to the focused signing or encryption class. Serialization can be compact, flattened JSON or general JSON depending on the operation/message shape. For multi-recipient JWE, recipient-specific wrapped/derived CEK material is not the same thing as the shared content-encryption output.

## 5. Relationships

- `../basic/` provides keys, signatures, HMAC, AEAD, KDF and encryption primitives.
- `../advisor/` provides JOSE name/enum/key-type and primitive-parameter mappings.
- `../cose/` provides analogous security-object processing over CBOR with COSE-specific identifiers and authenticated structures.
- JOSE uses JSON representations; `../cose/` uses `../../io/cbor/` for CBOR maps, arrays and byte strings.
- `../../../test/testcase/jose/` contains RFC examples, serialization tests, JWK cases and provider-gated additional-key tests.

### Focused implementation records

- [JOSE object model and context](jose-object-model.md) — in-memory context, recipient and signature state.
- [JWS signing and JWE encryption](jose-signing-encryption.md) — operation-specific signing input, key management, content encryption and serialization flows.
- [JWK and algorithm mapping](jose-key-and-algorithms.md) — conversion between JWK key material, JOSE identifiers and common crypto abstractions.
- [Legacy implementation-status note](jose-overview.md) — preserved historical status material; not the authoritative current support statement.

### Source-test evidence

- `testcase_rfc7515.cpp` includes the RFC 7515 A.1 HS256 example and checks generated compact output, then exercises flattened/general JSON forms.
- `testcase_rfc7516.cpp` exercises JWE examples across compact, flattened and general JSON serialization paths.
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

## 6. References

- RFC 7515 — JSON Web Signature (JWS).
- RFC 7516 — JSON Web Encryption (JWE).
- RFC 7517 — JSON Web Key (JWK).
- RFC 7518 — JSON Web Algorithms (JWA).
- RFC 7519 — JSON Web Token (JWT).
- RFC 7520 — Examples of Protecting Content Using JOSE.
- RFC 7638 — JSON Web Key (JWK) Thumbprint.
- RFC 8037 — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE.
- IANA JOSE registry — https://www.iana.org/assignments/jose/jose.xhtml
