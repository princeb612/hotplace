
## check1

|   |                       | AAD           | Context     | CEK                                           |
|-- |--                     |--             |--           |--                                             |
| - | A128KW                | Enc_structure | KDF_Context |                                               |
| - | A192KW                | Enc_structure | KDF_Context |                                               |
| - | A256KW                | Enc_structure | KDF_Context |                                               |
| - | DIRECT                | Enc_structure | KDF_Context |                                               |
| - | RSA_OAEP_SHA1         | Enc_structure | KDF_Context |                                               |
| - | RSA_OAEP_SHA256       | Enc_structure | KDF_Context |                                               |
| - | RSA_OAEP_SHA512       | Enc_structure | KDF_Context |                                               |
| - | HKDF_SHA_256          | Enc_structure | KDF_Context |                                               |
| - | HKDF_SHA_512          | Enc_structure | KDF_Context |                                               |
| - | HKDF_AES_128          | Enc_structure | KDF_Context |                                               |
| - | HKDF_AES_256          | Enc_structure | KDF_Context |                                               |
| - | ECDH_ES_HKDF_256      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  |
| - | ECDH_ES_HKDF_512      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  |
| - | ECDH_SS_HKDF_256      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  |
| - | ECDH_SS_HKDF_512      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  |
| - | ECDH_ES_A128KW        | Enc_structure | KDF_Context |                                               |
| - | ECDH_ES_A192KW        | Enc_structure | KDF_Context |                                               |
| - | ECDH_ES_A256KW        | Enc_structure | KDF_Context |                                               |
| - | ECDH_ES_A128KW        | Enc_structure | KDF_Context |                                               |
| - | ECDH_ES_A192KW        | Enc_structure | KDF_Context |                                               |
| - | ECDH_ES_A256KW        | Enc_structure | KDF_Context |                                               |
| - | AES_128_GCM           | Enc_structure | KDF_Context |                                               |
| - | AES_192_GCM           | Enc_structure | KDF_Context |                                               |
| - | AES_256_GCM           | Enc_structure | KDF_Context |                                               |
| - | AES_CBC_MAC_128_64    | Enc_structure | KDF_Context |                                               |
| - | AES_CBC_MAC_256_64    | Enc_structure | KDF_Context |                                               |
| - | AES_CBC_MAC_128_128   | Enc_structure | KDF_Context |                                               |
| - | AES_CBC_MAC_256_128   | Enc_structure | KDF_Context |                                               |
| - | CHACHA20_POLY1305     | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_16_64_128     | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_16_64_256     | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_64_64_128     | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_64_64_256     | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_16_128_128    | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_16_128_256    | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_64_128_128    | Enc_structure | KDF_Context |                                               |
| - | AES_CCM_64_128_256    | Enc_structure | KDF_Context |                                               |

* AES-CCM test failed

## check2

|   |               |
|-- |--             |
| - | HMAC_256_64   |
| - | HMAC_256_256  |
| - | HMAC_384_256  |
| - | HMAC_512_512  |
| - | RS256         |
| - | RS384         |
| - | RS512         |
| - | RS1           |
| - | ES256         |
| - | ES384         |
| - | ES512         |
| - | ES256K        |
| - | PS256         |
| - | PS384         |
| - | PS512         |
| - | EdDSA         |
| - | SHA1          |
| - | SHA256_64     |
| - | SHA256        |
| - | SHA512_256    |
| - | SHA384        |
| - | SHA512        |
| - | SHAKE128      |
| - | SHAKE256      |
