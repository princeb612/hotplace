
## block/stream cipher tested

| alg       | mode                                      |
| --        | --                                        |
| AES       | CBC,CFB,CFB1,CFB8,CTR,ECB,GCM,OFB,KEYWRAP |
| ARIA      | CBC,CFB,CFB1,CFB8,CTR,ECB,GCM,OFB         |
| CAMELLIA  | CBC,CFB,CFB1,CFB8,CTR,ECB,GCM,OFB         |
| SM4       | CBC,CFB,CTR,ECB,OFB                       |
| chacha20  | chacha20,chacha20-poly1305                |

## digest tested

| alg         |             |
| --          | --          |
| md4         | DIGEST,HMAC |
| md5         | DIGEST,HMAC |
| sha1        | DIGEST,HMAC |
| sha224      | DIGEST,HMAC |
| sha384      | DIGEST,HMAC |
| sha512      | DIGEST,HMAC |
| sha3 224    | DIGEST,HMAC |
| sha3 256    | DIGEST,HMAC |
| sha3 384    | DIGEST,HMAC |
| sha3 512    | DIGEST,HMAC |
| shake128    | DIGEST      |
| shake256    | DIGEST      |
| blake2b 512 | DIGEST,HMAC |
| blake2s 256 | DIGEST,HMAC |
| ripemd160   | DIGEST,HMAC |
| whirlpool   | DIGEST,HMAC |
