## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# JWS signing and JWE encryption

## 1. Role

This record covers the operation flow for JSON Web Signature (JWS) and JSON Web Encryption (JWE). It focuses on how JOSE constructs protocol-specific inputs and coordinates common cryptographic operations.

## 2. Data Model
### JWS

`json_object_signing` implements signing and verification. The public operations choose a `jws_t` algorithm and serialization form; internal `dosign()` / `doverify()` paths perform algorithm-specific work. The source represents HMAC, RSA PKCS#1 v1.5, RSA-PSS, ECDSA and EdDSA families. `json_web_signature` is a JWS-oriented helper.

```text
JWS header + payload
        ↓
 JOSE signing input
        ↓
 crypto/basic signature or MAC
        ↓
 signature bytes
        ↓
 compact / flattened JSON / general JSON
```

### JWE

`json_object_encryption` separates two stages:

1. **Key management** — obtain, derive, or wrap the CEK using algorithms such as RSA, AES-KW, ECDH-ES, AES-GCM-KW, and PBES2.
2. **Content encryption** — encrypt the payload with algorithms such as AES-CBC-HMAC or AES-GCM.

The source includes handling for direct (`dir`) and ECDH-ES cases, where CEK derivation differs from ordinary key wrapping.

## 3. Behavior Model
For multi-recipient JSON serialization, recipient-specific key-management results are represented separately from the shared content-encryption result. JWE compression is represented by `jose_deflate` in the context; this is protocol processing, not a replacement for the underlying cryptographic implementation.

The combined `json_object_signing_encryption` API exposes signing, verification, encryption and decryption through one JOSE-facing context. The focused signing and encryption classes contain the specific processing logic and composer paths.

## 4. Relationships

### Source-test evidence

`testcase_rfc7515.cpp` exercises sign/verify and checks the RFC 7515 A.1 HS256 compact serialization against a known output, with additional flattened/general JSON forms. `testcase_rfc7516.cpp` covers RFC 7516 examples. `testcase_rfc7520.cpp` exercises JWS and JWE examples, including multiple content-encryption and key-management combinations. The provided report lists 164 successful checks under the RFC 7520 group.

- `jose-object-model.md` documents context and recipient/signature state.
- `jose-key-and-algorithms.md` documents identifiers and JWK conversion.
- `../basic/` performs the primitive cryptographic operations.
- `../advisor/` supplies algorithm metadata used to connect JOSE names to cryptographic representations.

- `json_object_signing.hpp/.cpp`
- `json_object_encryption.hpp/.cpp`
- `json_object_signing_composer.cpp`
- `json_object_encryption_composer.cpp`
- `json_web_signature.hpp/.cpp`
- `test/testcase/jose/testcase_rfc7515.cpp`
- `test/testcase/jose/testcase_rfc7516.cpp`
- `test/testcase/jose/testcase_rfc7520.cpp`
