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

# JOSE object model and context

## 1. Role

This record describes the in-memory state used by hotplace's JOSE processing classes. The key architectural point is that JOSE state is represented separately from its eventual compact or JSON serialization.

## 2. Data Model
The central `jose_context_t` groups a key reference, protected-header data, encryption configurations, and signing entries:

```text
jose_context_t
 ├── crypto_key* key
 ├── protected_header
 ├── encryptions : jose_encryptions_map_t
 └── signs       : jose_signs_t
```

`jose_encryption_t` represents a content-encryption configuration and its recipient map, keyed by `jwa_t`. `jose_recipient_t` carries algorithm metadata, key, `kid`, headers, and parameters such as `epk`, `apu`/`apv`, PBES2 `p2s`/`p2c`, and AES-GCM key-wrap `iv`/`tag`.

`jose_sign_t` carries JWS header, payload, signature, key identifier, and selected `jws_t` algorithm. `jose_signs_t` can represent multiple signing entries, rather than only one compact signature.

## 3. Behavior Model
The data model preserves the distinction between a JWE content-encryption key (CEK) and the per-recipient operation that transports, wraps, or derives that key. `jose_serialization_t` selects compact, flattened JSON, or general JSON output without being the owner of the cryptographic state itself.

`json_object_signing_encryption` manages context lifecycle through `open`, `close`, and `clear_context`; callers should follow that lifecycle instead of assuming the context is a stateless value object.

## 5. Relationships

### Source-test evidence

The source tests exercise compact and JSON JWS forms, flattened and general JSON JWE forms, and JWK loading. For a direct JWS example, `test_rfc7515_A1()` signs and verifies the RFC 7515 A.1 HS256 vector in multiple serializations. The testcase map lists the other source functions.

```text
JSON / JOSE representation
        ↓
 jose_context_t + serialization choice
        ↓
 JWS / JWE processing
        ↓
 crypto_key + sdk/crypto/basic
        ↓
 provider-backed cryptographic operation
```

- [JWS/JWE processing flow](jose-signing-encryption.md)
- [JWK and algorithm mapping](jose-key-and-algorithms.md)
- `../basic/` and `../advisor/` provide the cryptographic and metadata boundary.

- `types.hpp`
- `json_object_signing_encryption.hpp/.cpp`
- `json_object_signing.hpp/.cpp`
- `json_object_encryption.hpp/.cpp`
- `test/testcase/jose/testcase_rfc7515.cpp`
- `test/testcase/jose/testcase_rfc7516.cpp`
