# JWS signing and JWE encryption

## JWS

`json_object_signing` implements RFC 7515 signing and verification. The public `sign()`/`verify()` operations select a `jws_t` algorithm and a JOSE serialization form, while the internal `dosign()`/`doverify()` operations perform the algorithm-specific cryptographic work.

Supported algorithm families represented in the current implementation include HMAC, RSA PKCS#1 v1.5, RSA-PSS, ECDSA and EdDSA.

`json_web_signature` provides the JWS-oriented signature helper used around this processing.

The important conceptual split is:

```text
JWS header + payload
        ↓
JOSE signing input
        ↓
crypto/basic signature or MAC
        ↓
JWS signature
        ↓
compact / JSON serialization
```

## JWE

`json_object_encryption` implements RFC 7516. It separates two cryptographic stages:

1. **Key management** — obtain, derive or wrap the CEK using algorithms such as RSA, AES-KW, ECDH-ES, AES-GCM-KW and PBES2.
2. **Content encryption** — encrypt the payload using `jwe_t` algorithms such as AES-CBC-HMAC or AES-GCM.

For multi-recipient JSON serialization, the same content-encryption result is associated with multiple recipient entries, each carrying its own key-management operation.

```text
plaintext
   ↓
content encryption (CEK)
   ↓
ciphertext + IV + tag

recipient key
   ↓
key management
   ↓
encrypted/derived CEK

        ↓
     JWE composer
        ↓
compact / flattened / JSON
```

The implementation has explicit handling for `dir` and `ECDH-ES`, where the CEK is obtained differently from ordinary wrapping algorithms.

## Combined orchestration

`json_object_signing_encryption` provides the common context lifecycle (`open`, `close`, `clear_context`) and exposes signing, verification, encryption and decryption operations through one JOSE-facing API.

This class is the main high-level entry point; the dedicated signing/encryption classes contain the more focused processing logic and composers.

## Compression

The JOSE context includes `jose_deflate`, corresponding to JWE compression processing. This is protocol-level handling rather than a replacement for the underlying crypto implementation.

## Tests

`test/testcase/jose/` exercises RFC 7515, 7516 and 7520 examples extensively, with JWK files and many RFC 7520 JWS/JWE fixtures. The RFC 7518 testcase provides the algorithm-level coverage.
