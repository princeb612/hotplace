# Encryption and AEAD

`sdk/crypto/basic/crypt` implements the encryption primitive layer used by protocol modules.  The public interfaces are `crypto_encrypt` for public-key encryption and `crypto_aead` for authenticated encryption.

## Encryption

`crypto_encrypt_builder` selects a `crypt_enc_t` scheme and creates a corresponding implementation.  The current public-key encryption classes cover RSA PKCS#1 v1.5 and RSA-OAEP variants.

The operation is deliberately small: a key plus plaintext/ciphertext enters the primitive, while algorithm identifiers and compatibility metadata remain the responsibility of `crypto/advisor`.

## AEAD

`crypto_aead_builder` selects a `crypto_scheme_t`, and `crypto_aead` exposes the common interface:

- key
- IV/nonce
- plaintext or ciphertext
- AAD
- authentication tag

The OpenSSL implementation provides the concrete cipher operation.  The same abstraction is used for protocol suites such as AES-GCM/CCM and therefore appears below TLS, JOSE and other higher-level code.

## Implementation shape

```text
crypto_encrypt_builder / crypto_aead_builder
        ↓
 generic crypto_* interface
        ↓
 OpenSSL implementation
        ↓
 EVP / cipher operation
```

`crypt/` also contains the CBC-HMAC-related path used by legacy protocol/test-vector cases.

## Tests

`test/testcase/crypto/crypt/` contains generic encryption/AEAD tests plus CAVP and RFC vectors, including RFC 3394 and RFC 7539 and CBC-HMAC TLS/JOSE vectors.
