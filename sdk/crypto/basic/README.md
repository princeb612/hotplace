
## block cipher tested

| alg       | CBC | CFB | CFB1 | CFB8 | CTR | ECB | GCM | OFB | KEYWRAP |
| --        | --  | --  | --   | --   | --  | --  | --  | --  | --      |
| AES       |  O  |  O  |  O   |  O   |  O  |  O  |  O  |  O  |    O    |
| ARIA      |  O  |  O  |  O   |  O   |  O  |  O  |  O  |  O  |         |
| BF        |  O  |  O  |      |      |     |  O  |     |  O  |         |
| CAMELLIA  |  O  |  O  |  O   |  O   |  O  |  O  |     |  O  |         |
| CAST      |  O  |  O  |      |      |     |  O  |     |  O  |         |
| DES       |  O  |  O  |      |      |     |  O  |     |  O  |         |
| IDEA      |  O  |  O  |      |      |     |  O  |     |  O  |         |
| RC2       |  O  |  O  |      |      |     |  O  |     |  O  |         |
| RC5       |  O  |  O  |      |      |     |  O  |     |  O  |         |
| SEED      |  O  |  O  |      |      |     |  O  |     |  O  |         |
| SM4       |  O  |  O  |      |      |     |  O  |     |  O  |         |

## stream cipher tested

  * chacha20
    * chacha20,chacha20-poly1305

## digest tested

### CMAC

  * AES-CBC-MAC

### HMAC

| alg         | DIGEST | HMAC |
| --          | --     | --   |
| md4         |    O   |  O   |
| md5         |    O   |  O   |
| sha1        |    O   |  O   |
| sha224      |    O   |  O   |
| sha384      |    O   |  O   |
| sha512      |    O   |  O   |
| sha3 224    |    O   |  O   |
| sha3 256    |    O   |  O   |
| sha3 384    |    O   |  O   |
| sha3 512    |    O   |  O   |
| shake128    |    O   |      |
| shake256    |    O   |      |
| blake2b 512 |    O   |  O   |
| blake2s 256 |    O   |  O   |
| ripemd160   |    O   |  O   |
| whirlpool   |    O   |  O   |

## KDF

  * HKDF
  * PBKDF2
  * scrypt
  * argon2d,argon2i,argon2id

#### block cipher

| algorithm   | key | iv |
| --          | --  | -- |
| AES128      | 16  | 16 |
| AES192      | 24  | 16 |
| AES256      | 32  | 16 |
| blowfish    | 16  |  8 |
| aria128     | 16  | 16 |
| aria192     | 24  | 16 |
| aria256     | 32  | 16 |
| camellia128 | 16  | 16 |
| camellia192 | 24  | 16 |
| camellia256 | 32  | 16 |
| chacha20    | 32  | 12 |

#### digest

| algorithm    | bits | dlen |
| md5          |  128 |   16 |
| sha1         |  160 |   20 |
| sha2_224     |  224 |   28 |
| sha2_256     |  256 |   32 |
| sha2_384     |  384 |   48 |
| sha2_512     |  512 |   64 |
| sha2_512_224 |  224 |   28 |
| sha2_512_256 |  256 |   32 |
| sha3_224     |  224 |   28 |
| sha3_256     |  256 |   32 |
| sha3_384     |  384 |   48 |
| sha3_512     |  512 |   64 |

#### Classification of Elliptic Curves
- Finite Field
  - Prime Field
    - Prime Field Curve (Fp)
      - y^2 = x^3 + ax + b mod p
      - P-256, P-384, P-521, ...
  - Binary Field
    - Binary Field Curve (F2m)
      - y^2 + xy = x^3 + ax^2 + b
      - B-163, B-233, B-283, K-163, K-233, ...
- Curve Form
  - Weierstrass
    - Weierstrass Curve
      - y^2 = x^3 + ax + b
  - Edwards
    - Edwards Curve
      - x^2 + y^2 = 1 + (d x^2 y^2)
      - Ed25519, Ed448
  - Montgomery
    - Montgomery Curve
      - By^2 = x^3 + Ax^2 + x
      - curve25519, curve448 (X25519, X448)
- Special Curve
  - Koblitz
    - Koblitz Curve
      - K-163, K-233, ...

#### OID
- reference
  - https://oid-base.com/
  - RFC 3279
- example
  - https://oid-base.com/cgi-bin/display?oid=1.2.840.10045.3.1&a=display
    - dot     : 1.2.840.10045.3.1.7
    - ASN.1   : {iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) prime256v1(7) }
    - ASN.1   : { 1 2 840 10045 3 1 7 }
    - OID-IRI : /1/2/840/10045/3/1/7
    - URN     : urn:oid:1.2.840.10045.3.1.7
  - https://oid-base.com/cgi-bin/display?oid=1.3.132.0.6&a=display
    - dot     : 1.3.132.0.6
    - ASN.1   : {iso(1) identified-organization(3) certicom(132) curve(0) secp112r1(6)}
    - ASN.1   : { 1 3 132 0 6 }
    - OID-IRI : /ISO/Identified-Organization/132/0/6
    - URN     : urn:oid:1.3.132.0.6
  - https://oid-base.com/cgi-bin/display?oid=1.3.36.3.3.2.8.1.1.1&a=display
    - dot     : 1.3.36.3.3.2.8.1.1.1
    - ASN.1   : {iso(1) identified-organization(3) teletrust(36) algorithm(3) signatureAlgorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) ellipticCurve(1) versionOne(1) brainpoolP160r1(1)}
    - ASN.1   : { 1 3 36 3 3 2 8 1 1 1 }
    - OID-IRI : /ISO/Identified-Organization/36/3/3/2/8/1/1/1
    - URN     : urn:oid:1.3.36.3.3.2.8.1.1.1
  - https://oid-base.com/cgi-bin/display?oid=1.3.101.110&a=display
    - dot     : 1.3.101.110
    - ASN.1   : {iso(1) identified-organization(3) thawte(101) id-X25519(110)}
    - ASN.1   : { 1 3 101 110 }
    - OID-IRI : /ISO/Identified-Organization/101/110
    - URN     : urn:oid:1.3.101.110
