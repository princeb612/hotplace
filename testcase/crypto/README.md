#### crypto

* test vector
  * CAVP
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

#### YAML schema

* CBC-HMAC JOSE schema

````
testvector:
  - example: string         # [mandatory] testcase
    schema: CBC-HMAC JOSE   # [mandatory] "CBC-HMAC JOSE"
    items:
      - item: string
        encalg: string      # [mandatory] algorithm
        macalg: string      # [mandatory] algorithm
        k: hexstring        # [mandatory] mackey || enckey
        p: hexstring        # [mandatory] PT
        iv: hexstring       # [mandatory] IV
        a: hexstring        # [mandatory] AAD
        q: hexstring        # [mandatory] Q = CBC-ENC(ENC_KEY, P || PS)
        s: hexstring        # [mandatory] S = IV || Q
        t: hexstring        # [mandatory] T = MAC(MAC_KEY, A || S || AL)
        c: hexstring        # [mandatory] CT = S || T
````

* CBC-HMAC JOSE TLS schema

````
testvector:
  - example: string         # [mandatory] testcase
    schema: CBC-HMAC TLS    # [mandatory] "CBC-HMAC TLS"
    items:
      - item: string        #
        flag: string        # [mandatory] "mac_then_encrypt"|"encrypt_then_mac"
        enckey: hexstring   # [mandatory] key
        iv: hexstring       # [mandatory] IV
        macalg: string      # [mandatory] algorithm
        mackey: hexstring   # [mandatory] MAC key
        aad: hexstring      # [mandatory] AAD
        pt: hexstring       # [mandatory] plaintext
        ct: hexstring       # [mandatory] ciphertext
````

* NIST CAVP block-ciphers TLS schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: BLOCK CIPHERS       # [mandatory] "BLOCK CIPHERS"
    items:
      - item: string            #
        alg: string             # [mandatory] algorithm
        key: hexstring          # [mandatory] key
        iv: hexstring           # [mandatory] IV
        pt: hexstring           # [mandatory] plaintext
        ct: hexstring           # [mandatory] ciphertext
````

* RFC 3394 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 3394            # [mandatory] "RFC 3394"
    items:
      - item: string            #
        alg: string             # [mandatory] "aes-128-wrap"|"aes-192-wrap"|"aes-256-wrap"
        kek: hexstring          # [mandatory] key encryption key
        key: hexstring          # [mandatory] key
        keydata: hexstring      # [mandatory] key data
````

* RFC 7439 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 7539            # [mandatory] "RFC 7539"
    items:
      - item: string            #
        alg: string             # [mandatory] "chacha20"|"chacha20-poly1305"
        key: hexstring          # [mandatory] key
        counter: int            # [mandatory] counter
        iv: hexstring           # [mandatory] IV
        aad: hexstring          # mandatory if chacha20-poly1305
        tag: hexstring          # mandatory if chacha20-poly1305
        pt: string              # [mandatory] plaintext
        ct: hexstring           # [mandatory] ciphertext
````

* NIST CAVP ECDSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: ECDSA TESTVECTOR    # [mandatory] "ECDSA TESTVECTOR"
    encoding: "base16"|"plain"  # [mandatory] m encoding
    items:
      - item: string            #
        curve: string           # [mandatory]
        m: hexstring            # [mandatory] message (see encoding)
        d: hexstring            # [mandatory] private
        x: hexstring            # [mandatory] public
        y: hexstring            # [mandatory] public
        k: hexstring            # [mandatory]
        r: hexstring            # [mandatory] R
        s: hexstring            # [mandatory] S
````

* NIST CAVP DSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: DSA PARAMETER       # [mandatory] "DSA PARAMETER"
    items:
      - item: string            # [mandatory] primary key
        p: hexstring            # [mandatory] prime
        q: hexstring            # [mandatory] subprime
        g: hexstring            # [mandatory] generator
  - example: string             # [mandatory] testcase
    schema: DSA TESTVECTOR      # [mandatory] "DSA TESTVECTOR"
    items:
      - item: string            #
        param: string           # [mandatory] foreign key (param) references DSA PARAMETER (item)
        alg: string             # [mandatory]
        m: hexstring            # [mandatory]
        x: hexstring            # [mandatory] private
        y: hexstring            # [mandatory] public
        k: hexstring            # [mandatory]
        r: hexstring            # [mandatory] R
        s: hexstring            # [mandatory] S
````

* NIST CAVP RSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RSA KEY             # [mandatory] "RSA KEY"
    items:
      - item: string            # [mandatory] primary key
        n: hexstring            # [mandatory] modulus
        e: hexstring            # [mandatory] public exponent
        d: hexstring            # [mandatory] private exponent
  - example: string             # [mandatory] testcase
    schema: RSA PKCS 1.5        # [mandatory] "RSA PKCS 1.5"
    items:
      - item: string            #
        key: string             # [mandatory] foreign key (key) references RSA KEY (item)
        alg: string             # [mandatory] algorithm
        m: hexstring            # [mandatory] message
        s: hexstring            # [mandatory] signature
  - example: string             # [mandatory] testcase
    schema: RSA PSS             # [mandatory] "RSA PSS"
    items:
      - item: string            #
        key: string             # [mandatory] foreign key (key) references RSA KEY (item)
        alg: string             # [mandatory] algorithm
        m: hexstring            # [mandatory] message
        s: hexstring            # [mandatory] signature
        salt: hexstring         # [mandatory] salt
````
