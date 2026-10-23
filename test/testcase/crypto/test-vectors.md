## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Test Vectors

## 1. Role

This document records testcase organization, test-vector schema, or reference material for the crypto test area. Its presence does not by itself establish runtime verification.

## 2. Test model

#### crypto

* test vector
1.   * CAVP
    * Block Ciphers
      * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
      * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
    * Digital Signatures
      * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/digital-signatures
      * FIPS 186-2 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2ecdsatestvectors.zip
      * FIPS 186-4 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip
  * AES
    * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
  * ChaCha20
    * RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
  * AES-CBC-HMAC (JOSE, JWE)
    * RFC 7516 JSON Web Encryption (JWE)
    * https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
  * AES-CBC-HMAC (TLS)
    * https://tls12.xargs.org/#client-handshake-finished
  * MAC
    * RFC 4226 HOTP: An HMAC-Based One-Time Password Algorithm
    * RFC 4231 Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
    * RFC 4493 The AES-CMAC Algorithm
    * RFC 6238 TOTP: Time-Based One-Time Password Algorithm
  * DSA
    * RFC 6979 Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)
  * KDF
    * RFC 4615 The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128 (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)
    * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    * RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
    * RFC 7914 The scrypt Password-Based Key Derivation Function
    * RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
  * key
    * RFC 7748
      * 6.1.  Curve25519
      * 6.2.  Curve448
* reference
2.   * Hybrid Public Key Encryption
    * RFC 9180 Hybrid Public Key Encryption
    * [Hybrid Public Key Encryption (HPKE)](https://cryptosys.net/pki/hpke.html)

## 3. Example: Source inventory and test-vector use

1. The retained material is a schema/reference or directory-level record. Consult the listed testcase source files to determine which functions consume these inputs and what assertions they make.

## 4. Test and verification status

### 4.1 Source-level coverage

No claim of algorithmic coverage is inferred from this reference document alone. Coverage must be established from the consuming C++ testcase functions and their expected-result checks.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Crypto implementation: `sdk/crypto/README.md`
- Test sources and vector consumers are located in the corresponding sibling testcase directories.
- Related testcase source: `test/testcase/crypto/sample.cpp`



## 6. References

No external references are currently listed.
