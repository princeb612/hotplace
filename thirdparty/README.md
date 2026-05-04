### thirdparty

* build
  ./make.sh debug

* thirdparty

| OSS          | brief       | description                                                              |
| --           | --          | --                                                                       |
| openssl      | CRYPTO, TLS | general-purpose cryptography and secure communication                    |
| jansson      | JSON        | encoding, decoding and manipulating JSON data                            |
| zlib         | compression | A Massively Spiffy Yet Delicately Unobtrusive Compression Library        |
| liboqs       | PQC         | quantum-safe cryptographic algorithms                                    |
| oqs-provider | PQC         | quantum-safe cryptography (QSC) in a standard OpenSSL (3.x) distribution |

* summary
  * openssl 1.1.1 or newer
    * RSA-OAEP-256
    * Ed25519 Ed448 X25519 X448
    * sha3
  * openssl 3.0, 3.1
    * EVP_CIPHER_fetch/EVP_CIPHER_free, EVP_MD_fetch/EVP_MD_free
    * truncated sha ("sha2-512/224", "sha2-512/256")
    * failed to load PEM file containing HMAC private key
  * openssl 3.2
    * argon2d, argon2i, argon2id
  * openssl 3.5
    * ML-KEM, ML-DSA

* comments
  * openssl
    * MSVC
      * [MUST] manual build
    * 3.5.5, 3.6.1
      * [# 3.6.1 fails to build with MSYS2 (MingW64) on Windows 11.](https://github.com/openssl/openssl/issues/29818)
