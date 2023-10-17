
## check1

|   |                       | AAD           | Context     | CEK                                           | Final |
|-- |--                     |--             |--           |--                                             |--     |
| - | A128KW                | Enc_structure |             |                                               |       |
| - | A192KW                | Enc_structure |             |                                               |       |
| - | A256KW                | Enc_structure |             |                                               |       |
| - | DIRECT                | Enc_structure |             |                                               |       |
| - | RSA_OAEP_SHA1         | Enc_structure |             |                                               |       |
| - | RSA_OAEP_SHA256       | Enc_structure |             |                                               |       |
| - | RSA_OAEP_SHA512       | Enc_structure |             |                                               |       |
| - | HKDF_SHA_256          | Enc_structure |             |                                               |       |
| - | HKDF_SHA_512          | Enc_structure |             |                                               |       |
| - | HKDF_AES_128          | Enc_structure |             |                                               |       |
| - | HKDF_AES_256          | Enc_structure |             |                                               |       |
| - | ECDH_ES_HKDF_256      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  | PASS  |
| - | ECDH_ES_HKDF_512      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  | PASS  |
| - | ECDH_SS_HKDF_256      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  | PASS  |
| - | ECDH_SS_HKDF_512      | Enc_structure | KDF_Context | kdf_hkdf (dlen,ecdh_shared,salt,context,prf)  | PASS  |
| - | ECDH_ES_A128KW        | Enc_structure |             |                                               |       |
| - | ECDH_ES_A192KW        | Enc_structure |             |                                               |       |
| - | ECDH_ES_A256KW        | Enc_structure |             |                                               |       |
| - | ECDH_ES_A128KW        | Enc_structure |             |                                               |       |
| - | ECDH_ES_A192KW        | Enc_structure |             |                                               |       |
| - | ECDH_ES_A256KW        | Enc_structure |             |                                               |       |
| - | AES_128_GCM           | Enc_structure |             |                                               |       |
| - | AES_192_GCM           | Enc_structure |             |                                               |       |
| - | AES_256_GCM           | Enc_structure |             |                                               |       |
| - | AES_CBC_MAC_128_64    | Enc_structure |             |                                               |       |
| - | AES_CBC_MAC_256_64    | Enc_structure |             |                                               |       |
| - | AES_CBC_MAC_128_128   | Enc_structure |             |                                               |       |
| - | AES_CBC_MAC_256_128   | Enc_structure |             |                                               |       |
| - | CHACHA20_POLY1305     | Enc_structure |             |                                               |       |
| - | AES_CCM_16_64_128     | Enc_structure |             |                                               |       |
| - | AES_CCM_16_64_256     | Enc_structure |             |                                               |       |
| - | AES_CCM_64_64_128     | Enc_structure |             |                                               |       |
| - | AES_CCM_64_64_256     | Enc_structure |             |                                               |       |
| - | AES_CCM_16_128_128    | Enc_structure |             |                                               |       |
| - | AES_CCM_16_128_256    | Enc_structure |             |                                               |       |
| - | AES_CCM_64_128_128    | Enc_structure |             |                                               |       |
| - | AES_CCM_64_128_256    | Enc_structure |             |                                               |       |

## check2

|   |               |               | Final |
|-- |--             | --            | --    |
| - | HMAC_256_64   | Sig_structure |       |
| - | HMAC_256_256  | Sig_structure |       |
| - | HMAC_384_256  | Sig_structure |       |
| - | HMAC_512_512  | Sig_structure |       |
| - | RS256         | Sig_structure | PASS  |
| - | RS384         | Sig_structure | PASS  |
| - | RS512         | Sig_structure | PASS  |
| - | RS1           | Sig_structure |       |
| - | ES256         | Sig_structure | PASS  |
| - | ES384         | Sig_structure | PASS  |
| - | ES512         | Sig_structure | PASS  |
| - | ES256K        | Sig_structure |       |
| - | PS256         | Sig_structure | PASS  |
| - | PS384         | Sig_structure | PASS  |
| - | PS512         | Sig_structure | PASS  |
| - | EdDSA         | Sig_structure | PASS  |
| - | SHA1          | Sig_structure |       |
| - | SHA256_64     | Sig_structure |       |
| - | SHA256        | Sig_structure |       |
| - | SHA512_256    | Sig_structure |       |
| - | SHA384        | Sig_structure |       |
| - | SHA512        | Sig_structure |       |
| - | SHAKE128      | Sig_structure |       |
| - | SHAKE256      | Sig_structure |       |
