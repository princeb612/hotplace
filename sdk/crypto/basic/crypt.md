## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Encryption and AEAD

## 1. Role

`sdk/crypto/basic/crypt` implements the encryption primitive layer used by protocol modules.  The public interfaces are `crypto_encrypt` for public-key encryption and `crypto_aead` for authenticated encryption.

## 2. Model

### Encryption

`crypto_encrypt_builder` selects a `crypt_enc_t` scheme and creates a corresponding implementation.  The current public-key encryption classes cover RSA PKCS#1 v1.5 and RSA-OAEP variants.

The operation is deliberately small: a key plus plaintext/ciphertext enters the primitive, while algorithm identifiers and compatibility metadata remain the responsibility of `crypto/advisor`.

### AEAD

`crypto_aead_builder` selects a `crypto_scheme_t`, and `crypto_aead` exposes the common interface:

- key
- IV/nonce
- plaintext or ciphertext
- AAD
- authentication tag

The OpenSSL implementation provides the concrete cipher operation.  The same abstraction is used for protocol suites such as AES-GCM/CCM and therefore appears below TLS, JOSE and other higher-level code.

## 3. Important behavior and lifetime

### Implementation shape

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

## 4. Example from the source tests

### Tests

`test/testcase/crypto/crypt/` contains generic encryption/AEAD tests plus CAVP and RFC vectors, including RFC 3394 and RFC 7539 and CBC-HMAC TLS/JOSE vectors.

## 5. Relationships

Related implementation modules and protocol boundaries are recorded here where identified.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
