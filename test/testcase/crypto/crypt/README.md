## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Encryption and AEAD Testcases

## 1. Role

This directory contains test sources for encryption and aead in hotplace. The category covers public-key encryption, authenticated encryption, cipher modes, and vector-backed paths.

## 2. Test model

### Encryption and AEAD testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_aead_ccm.cpp`
* `testcase_cipher_encrypt.cpp`
* `testcase_crypto_aead.cpp`
* `testcase_crypto_encrypt.cpp`
* `testcase_openssl_crypt.cpp`
* `testvector_cavp_blockciphers.cpp`
* `testvector_cbc_hmac_jose.cpp`
* `testvector_cbc_hmac_tls.cpp`
* `testvector_rfc3394.cpp`
* `testvector_rfc7539.cpp`

#### test data / build files

* `testvector_cavp_blockciphers.yml`
* `testvector_cbc_hmac_jose.yml`
* `testvector_cbc_hmac_tls.yml`
* `testvector_rfc3394.yml`
* `testvector_rfc7539.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

Source files in this directory: `testcase_aead_ccm.cpp`, `testcase_cipher_encrypt.cpp`, `testcase_crypto_aead.cpp`, `testcase_crypto_encrypt.cpp`, `testcase_openssl_crypt.cpp`, `testvector_cavp_blockciphers.cpp`, `testvector_cbc_hmac_jose.cpp`, `testvector_cbc_hmac_tls.cpp`, `testvector_rfc3394.cpp`, `testvector_rfc7539.cpp`

## 3. Example: Encryption and AEAD source example

`testcase_crypto_aead.cpp` defines `test_crypto_aead()` and records both encrypt and decrypt outcomes. Other sources cover CCM, OpenSSL-specific operations, block-cipher vectors, RFC 3394 key wrap, RFC 7539 ChaCha20/Poly1305, and CBC-HMAC JOSE/TLS vectors.

## 4. Test and verification status

### 4.1 Source-level coverage

The inspected AEAD source records encrypt/decrypt return outcomes; vector-backed sources provide known-input paths. The existence of vectors alone does not establish that every vector passed in a given environment.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Implementation documentation: `sdk/crypto/basic/crypt/README.md`; cipher inventory is preserved in `sdk/crypto/basic/README.md` under Developer Notes
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 6. References

Source files in this directory:
- `test/testcase/crypto/crypt/testcase_aead_ccm.cpp`
- `test/testcase/crypto/crypt/testcase_cipher_encrypt.cpp`
- `test/testcase/crypto/crypt/testcase_crypto_aead.cpp`
- `test/testcase/crypto/crypt/testcase_crypto_encrypt.cpp`
- `test/testcase/crypto/crypt/testcase_openssl_crypt.cpp`
- `test/testcase/crypto/crypt/testvector_cavp_blockciphers.cpp`
- `test/testcase/crypto/crypt/testvector_cbc_hmac_jose.cpp`
- `test/testcase/crypto/crypt/testvector_cbc_hmac_tls.cpp`
- `test/testcase/crypto/crypt/testvector_rfc3394.cpp`
- `test/testcase/crypto/crypt/testvector_rfc7539.cpp`
