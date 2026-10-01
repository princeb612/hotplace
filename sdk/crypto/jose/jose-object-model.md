# JOSE object model and context

## Purpose

The hotplace JOSE implementation keeps protocol-level state in a small set of structures rather than exposing the JSON representation directly to every cryptographic operation.

The central context is `jose_context_t`:

```text
jose_context_t
 ├── crypto_key* key
 ├── protected_header
 ├── encryptions : jose_encryptions_map_t
 └── signs       : jose_signs_t
```

This context is shared by the signing/encryption orchestration class and the JWS/JWE helpers.

## Encryption state

`jose_encryption_t` represents one content-encryption configuration. It owns the common protected/header data and a recipient map keyed by `jwa_t`.

A recipient (`jose_recipient_t`) carries the algorithm metadata, key, `kid`, header and algorithm-specific parameters such as:

- `epk` for ECDH-ES
- `apu` / `apv`
- `p2s` / `p2c` for PBES2
- `iv` / `tag` for AES-GCM key wrapping

The implementation therefore models the JWE distinction between the content-encryption key (CEK) and the mechanisms used to deliver or derive that CEK to recipients.

## Signing state

`jose_sign_t` contains the JWS header, payload, signature, key id and selected `jws_t` algorithm. Multiple entries are kept in `jose_signs_t`, which allows the implementation to represent multi-signature JSON serialization rather than only the compact single-signature form.

## Serialization

`jose_serialization_t` selects the external representation, including compact and JSON/flattened forms. The internal context is deliberately independent of that serialization so that the same cryptographic state can be composed into the requested representation.

## Boundary with crypto/basic

The JOSE layer does not redefine RSA, ECDSA, HMAC, AES, ECDH, KDF, or key storage. It maps JOSE identifiers and protocol parameters onto the common crypto implementation.

```text
JSON / JOSE representation
        ↓
 jose_context_t
        ↓
 JWS / JWE processing
        ↓
 crypto_key + crypto/basic
        ↓
 OpenSSL / cryptographic primitive
```

This separation is one of the main structural points worth remembering when returning to the source later.
