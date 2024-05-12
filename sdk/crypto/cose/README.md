- party : apu-id/nonce/other, apv-id/nonce/other
- epk   : ephemeral key
- s-key : static key
- s-kid : staic kid

| Implemented | Name      | Value | Description                                | aad | salt| party | epk | s-key | s-kid | comments |
|-- |--                   |--     |--                                                    |-- |-- |-- |-- |-- |-- |--                |
| O | ES256               | -7    | ECDSA w/ SHA-256                                     |   |   |   |   |   |   | kty:EC           |
| O | ES384               | -35   | ECDSA w/ SHA-384                                     |   |   |   |   |   |   | kty:EC           |
| O | ES512               | -36   | ECDSA w/ SHA-512                                     |   |   |   |   |   |   | kty:EC           |
| O | EdDSA               | -8    | EdDSA                                                |   |   |   |   |   |   | kty:OKP          |
| O | HMAC 256/64         | 4     | HMAC w/ SHA-256 truncated to 64 bits                 |   |   |   |   |   |   |                  |
| O | HMAC 256/256        | 5     | HMAC w/ SHA-256                                      |   |   |   |   |   |   |                  |
| O | HMAC 384/384        | 6     | HMAC w/ SHA-384                                      |   |   |   |   |   |   |                  |
| O | HMAC 512/512        | 7     | HMAC w/ SHA-512                                      |   |   |   |   |   |   |                  |
| O | AES-MAC 128/64      | 14    | AES-MAC 128-bit key, 64-bit tag                      |   |   |   |   |   |   |                  |
| O | AES-MAC 256/64      | 15    | AES-MAC 256-bit key, 64-bit tag                      |   |   |   |   |   |   |                  |
| O | AES-MAC 128/128     | 25    | AES-MAC 128-bit key, 128-bit tag                     |   |   |   |   |   |   |                  |
| O | AES-MAC 256/128     | 26    | AES-MAC 256-bit key, 128-bit tag                     |   |   |   |   |   |   |                  |
| O | A128GCM             | 1     | AES-GCM mode w/ 128-bit key, 128-bit tag             | o |   |   |   |   |   |                  |
| O | A192GCM             | 2     | AES-GCM mode w/ 192-bit key, 128-bit tag             | o |   |   |   |   |   |                  |
| O | A256GCM             | 3     | AES-GCM mode w/ 256-bit key, 128-bit tag             | o |   |   |   |   |   |                  |
| O | AES-CCM-16-64-128   | 10    | AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce  | o |   |   |   |   |   |                  |
| O | AES-CCM-16-64-256   | 11    | AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce  | o |   |   |   |   |   |                  |
| O | AES-CCM-64-64-128   | 12    | AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce   | o |   |   |   |   |   |                  |
| O | AES-CCM-64-64-256   | 13    | AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce   | o |   |   |   |   |   |                  |
| O | AES-CCM-16-128-128  | 30    | AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce | o |   |   |   |   |   |                  |
| O | AES-CCM-16-128-256  | 31    | AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce | o |   |   |   |   |   |                  |
| O | AES-CCM-64-128-128  | 32    | AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce  | o |   |   |   |   |   |                  |
| O | AES-CCM-64-128-256  | 33    | AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce  | o |   |   |   |   |   |                  |
| X | ChaCha20/Poly1305   | 24    | ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag        |   |   |   |   |   |   | nonce wo counter |
| O | direct              | -6    | Direct use of CEK                                    |   |   |   |   |   |   | kty:oct(symm)    |
| O | direct+HKDF-SHA-256 | -10   | Shared secret w/ HKDF and SHA-256                    |   | o | o |   |   |   |                  |
| O | direct+HKDF-SHA-512 | -11   | Shared secret w/ HKDF and SHA-512                    |   | o | o |   |   |   |                  |
| O | direct+HKDF-AES-128 | -12   | Shared secret w/ AES-MAC 128-bit key                 |   | o | o |   |   |   |                  |
| O | direct+HKDF-AES-256 | -13   | Shared secret w/ AES-MAC 256-bit key                 |   | o | o |   |   |   |                  |
| O | A128KW              | -3    | AES Key Wrap w/ 128-bit key                          |   |   |   |   |   |   |                  |
| O | A192KW              | -4    | AES Key Wrap w/ 192-bit key                          |   |   |   |   |   |   |                  |
| O | A256KW              | -5    | AES Key Wrap w/ 256-bit key                          |   |   |   |   |   |   |                  |
| O | ECDH-ES + HKDF-256  | -25   | ECDH ES w/ HKDF - SHA-256                            |   | o | o | o |   |   |                  |
| O | ECDH-ES + HKDF-512  | -26   | ECDH ES w/ HKDF - SHA-512                            |   | o | o | o |   |   |                  |
| O | ECDH-SS + HKDF-256  | -27   | ECDH SS w/ HKDF - SHA-256                            |   | o | o |   | o | o |                  |
| O | ECDH-SS + HKDF-512  | -28   | ECDH SS w/ HKDF - SHA-512                            |   | o | o |   | o | o |                  |
| O | ECDH-ES + A128KW    | -29   | ECDH ES w/ HKDF - SHA-256 A128KW                     |   | o | o | o |   |   |                  |
| O | ECDH-ES + A192KW    | -30   | ECDH ES w/ HKDF - SHA-256 A192KW                     |   | o | o | o |   |   |                  |
| O | ECDH-ES + A256KW    | -31   | ECDH ES w/ HKDF - SHA-256 A128KW                     |   | o | o | o |   |   |                  |
| O | ECDH-SS + A128KW    | -32   | ECDH SS w/ HKDF - SHA-256 A128KW                     |   | o | o |   | o | o |                  |
| O | ECDH-SS + A192KW    | -33   | ECDH SS w/ HKDF - SHA-256 A192KW                     |   | o | o |   | o | o |                  |
| O | ECDH-SS + A256KW    | -34   | ECDH SS w/ HKDF - SHA-256 A128KW                     |   | o | o |   | o | o |                  |
