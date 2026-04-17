#### crypto

* test vector
  * AES
    * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
    * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
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
    * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/digital-signatures
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
  * Hybrid Public Key Encryption
    * RFC 9180 Hybrid Public Key Encryption
    * [Hybrid Public Key Encryption (HPKE)](https://cryptosys.net/pki/hpke.html)

#### ECDSA signature/hash algorithm

| hash   | sizeof R+S |
|   --   |     --     |
| sha1   | 40         |
| sha224 | 56         |
| sha256 | 64         |
| sha384 | 96         |
| sha512 | 132        |


- sha1 | sha2_224 | sha2_256 | sha2_384 | sha2_512
  - NID_secp112r1 : secp112r1, wap-wsg-idm-ecid-wtls6
  - NID_secp112r2 : secp112r2
  - NID_secp128r1 : secp128r1
  - NID_secp128r2 : secp128r2
  - NID_secp160k1 : ansip160k1, secp160k1
  - NID_secp160r1 : ansip160r1, secp160r1, wap-wsg-idm-ecid-wtls7
  - NID_secp160r2 : ansip160r2, secp160r2
  - NID_sect113r2 : sect113r2
  - NID_sect131r1 : sect131r1
  - NID_sect131r2 : sect131r2
  - NID_brainpoolP160r1 : brainpoolP160r1
  - NID_brainpoolP160t1 : brainpoolP160t1
- sha2_224 | sha2_256 | sha2_384 | sha2_512
  - NID_secp192k1 : ansip192k1, secp192k1
  - NID_X9_62_prime192v1 : P-192, prime192v1, secp192r1
  - NID_secp224k1 : ansip224k1, secp224k1
  - NID_secp224r1 : P-224, ansip224r1, secp224r1, wap-wsg-idm-ecid-wtls12
  - NID_sect163k1 : K-163, ansit163k1, sect163k1, wap-wsg-idm-ecid-wtls3
  - NID_sect163r1 : ansit163r1, sect163r1
  - NID_sect163r2 : B-163, ansit163r2, sect163r2
  - NID_sect193r1 : ansit193r1, sect193r1
  - NID_sect193r2 : sect193r2
  - NID_brainpoolP192r1 : brainpoolP192r1
  - NID_brainpoolP192t1 : brainpoolP192t1
  - NID_brainpoolP224r1 : brainpoolP224r1
  - NID_brainpoolP224t1 : brainpoolP224t1
- sha2_256 | sha2_384 | sha2_512
  - NID_secp256k1 : ansip256k1, secp256k1
  - NID_X9_62_prime256v1 : P-256, prime256v1, secp256r1
  - NID_sect233k1 : K-233, ansit233k1, sect233k1, wap-wsg-idm-ecid-wtls10
  - NID_sect233r1 : B-233, ansit233r1, sect233r1, wap-wsg-idm-ecid-wtls11
  - NID_sect239k1 : ansit239k1, sect239k1
  - NID_brainpoolP256r1 : brainpoolP256r1
  - NID_brainpoolP256t1 : brainpoolP256t1
- sha2_384 | sha2_512
  - NID_secp384r1 : P-384, ansip384r1, secp384r1
  - NID_sect283k1 : K-283, ansit283k1, sect283k1
  - NID_sect283r1 : B-283, ansit283r1, sect283r1
  - NID_brainpoolP320r1 : brainpoolP320r1
  - NID_brainpoolP320t1 : brainpoolP320t1
  - NID_brainpoolP384r1 : brainpoolP384r1
  - NID_brainpoolP384t1 : brainpoolP384t1
- sha2_512
  - NID_secp521r1 : P-521, ansip521r1, secp521r1
  - NID_secp521r1 : sect113r1, wap-wsg-idm-ecid-wtls4
  - NID_sect409k1 : K-409, ansit409k1, sect409k1
  - NID_sect409r1 : B-409, ansit409r1, sect409r1
  - NID_brainpoolP512r1 : brainpoolP512r1
  - NID_brainpoolP512t1
- N/A
  - NID_sect571k1 : K-571, ansit571k1, sect571k1
  - NID_sect571r1 : B-571, ansit571r1, sect571r1

#### PQC

[Post-Quantum Cryptography](https://seed.kisa.or.kr/kisa/ngc/pqc.do)
NIST 2022
|                    |               |                                                            |
| --                 | --            | --                                                         |
| Crystals-Kyber     | Lattice-based | ML-KEM (Module Lattice-Based Key Encapsulation Mechanism)  |
| Crystals-Dilithium | Lattice-based | DL-DSA (Dilithium Digital Signature Algorithm)             |
| FALCON             | Lattice-based | FN-DSA (Falcon Digital Signature Algorithm)                |
| SPHINCS+           | Hash-based    | SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) |

#### oqs-provider

* [oqs-provider](https://github.com/open-quantum-safe/oqs-provider/)
- [ ] study
  - [x] encode/decode
    - [x] DER, PEM
    - [x] public, private, encrypted private
  - [x] KEM
    - [x] build OQS_KEM_ENCODERS
    - [x] encapsulate/decapsulate
  - [x] DSA
    - [x] sign/verify
  - [ ] test vector
    - [ ] [ML-DSA-keyGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204)
    - [ ] [ML-DSA-sigGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204)
    - [ ] [ML-DSA-sigVer-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)
    - [ ] [ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)
    - [ ] [ML-KEM-encapDecap-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)
