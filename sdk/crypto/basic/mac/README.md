#### CBC-HMAC survey

| specification            | type | tag              | example                                                  |
| --                       | --   | --               | --                                                       |
| JOSE                     | EtM  | separated tag    | JOSE A128CBC-HS256, A192CBC-HS384, A256CBC-HS512         |
| TLS w/o encrypt_then_mac | MtE  | nested tag       | TLS 1.2 w/o encrypt_then_mac extension                   |
| TLS encrypt_then_mac     | EtM  | concatenated tag | TLS 1.2 encrypt_then_mac extension, TLS 1.3 ciphersuites |

* JOSE
  * EtM encrypt-then-mac
    * separated tag = MAC(AAD || IV || ciphertext || uint64(AAD.length))
    * for more details
      * Authenticated Encryption with AES-CBC and HMAC-SHA (JOSE)
      * RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
      * https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
        * tag = HMAC(aad || iv || ciphertext || uint64(aad_len))
      * https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
        * 2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
        * 2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
        * 2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
        * 2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32
      * JOSE
        * "A128CBC-HS256"
        * "A192CBC-HS384"
        * "A256CBC-HS512"
* TLS
  * MtE mac-then-encrypt (w/o encrypt_then_mac extension)
    * AAD = uint64(sequence) || uint8(type) || uint16(version)
    * nested tag = MAC(AAD || uint16(plaintext.length) || plaintext)
    * ciphertext = CBC(plaintext || tag || pad1)
    * image = ciphertext
    * for more details
      * https://tls12.xargs.org
  * EtM encrypt-then-mac (encrypt_then_mac extension)
    * ciphertext = CBC(plaintext)
    * AAD = uint64(sequence) || uint8(type) || uint16(version) || uint16(ciphertext.length)
    * concatenated tag = CBC-HMAC(AAD || ciphertext)
    * image = CBC(plaintext) || tag
    * for more details
      * RFC 7366 Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
