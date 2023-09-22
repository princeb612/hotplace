
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
