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

* CBC-HMAC
  * MtE (mac-then-encrypt)
    * https://tls12.xargs.org/#client-handshake-finished
      * 00000000 : 16 03 03 00 40 40 41 42 43 44 45 46 47 48 49 4A | ....@@ABCDEFGHIJ
      * 00000010 : 4B 4C 4D 4E 4F 22 7B C9 BA 81 EF 30 F2 A8 A7 8F | KLMNO"{....0....
      * 00000020 : F1 DF 50 84 4D 58 04 B7 EE B2 E2 14 C3 2B 68 92 | ..P.MX.......+h.
      * 00000030 : AC A3 DB 7B 78 07 7F DD 90 06 7C 51 6B AC B3 BA | ...{x.....|Qk...
      * 00000040 : 90 DE DF 72 0F -- -- -- -- -- -- -- -- -- -- -- | ...r.
    * encrypted handshake
      * uint8(type)       := 16
      * uint16(version)   := 0303
      * uint16(length)    := 0040
      * explicit IV       := 404142434445464748494A4B4C4D4E4F
      * ciphertext        := 227bc9ba81ef30f2a8a78ff1df50844d5804b7eeb2e214c32b6892aca3db7b78077fdd90067c516bacb3ba90dedf720f
    * comments
      * ciphersuite       := TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
      * sequence          := uint64(sequence)
      * AAD               := uint64(sequence) || uint8(type) || uint16(version) = 0000000000000000160303
      * enckey            := f656d037b173ef3e11169f27231a84b6
      * IV                := 404142434445464748494a4b4c4d4e4f
      * plaintext         := CBC-DECRYPT(enckey, iv, ciphertext) = content || mac || pad1 = 1400000ccf919626f1360c536aaad73a || a5a03d233056e4ac6eba7fd9e5317fac2db5b70e || 0b
      * mac_calc          := HMAC(mackey, AAD || content.length || content) = a5a03d233056e4ac6eba7fd9e5317fac2db5b70e
      * authenticate      := true (mac_calc == mac)
      * content(finished) := 1400000ccf919626f1360c536aaad73a
  * EtM (encrypt-then-mac)
    * test/tls/tls12/tls12etm.pcapng
      * client finished
      * 00000000 : 16 03 03 00 50 b2 08 4a 5b 1d d6 15 cd 05 6d 1f
      * 00000010 : 28 8f b8 e5 7b 7e eb d2 6f bb 00 18 32 c0 6c de
      * 00000020 : 4b 8f a4 77 10 43 71 e5 ba 2a 09 1b 70 3b bc 80
      * 00000030 : 69 bc 97 bc 2d d0 d2 36 fa 30 89 55 3b 17 e9 6e
      * 00000040 : c6 a4 64 10 c0 00 2d ab 9e 5c e6 df b4 a8 53 9c
      * 00000050 : 90 63 48 d9 ab
    * encrypted handshake
      * uint8(type)     := 16
      * uint16(version) := 0303
      * uint16(length)  := 0050
      * ciphertext      := b2084a5b1dd615cd056d1f288fb8e57b7eebd26fbb001832c06cde4b8fa477104371e5ba2a091b703bbc8069bc97bc2d
      * mac             := d0d236fa3089553b17e96ec6a46410c0002dab9e5ce6dfb4a8539c906348d9ab
    * comments
      * ciphersuite     := TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
      * enckey          := f656d037b173ef3e11169f27231a84b6
      * IV              := 404142434445464748494a4b4c4d4e4f
      * mackey          := 1b7d117c7d5f690bc263cae8ef60af0f1878acc2
      * sequence        := uint64(sequence)
      * AAD             := uint64(sequence) || uint8(type) || uint16(version) = 0000000000000000160303
      * mac_calc        := HMAC(mackey, uint64(sequence) || uint8(type) || uint16(version) || ciphertext.length || ciphertext)
      * authenticate    := true (mac_calc == mac)
      * plaintext       := CBC-DECRYPT(enckey, IV, ciphertext) = 16bytes || content || pad1 = cace85bac5cfeea0bb0ae507869d2e4c || 1400000c9bf2cb3b4a834cc4dfa8478f || 0f
  * encrypted handshake image
    * unprotected
      * uint8(type)
      * uint16(version)
      * uint16(length)
    * MtE protected
      * 16(IV)
      * ciphertext := CBC-ENCRYPT(enckey, IV, content || mac || pad1)
    * EtM protected
      * ciphertext := CBC-ENCRYPT(enckey, IV, 16bytes || content || pad1)
