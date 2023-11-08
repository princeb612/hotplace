party : apu-id/nonce/other, apv-id/nonce/other
epk   : ephemeral key
s-key : static key
s-kid : staic kid

| Name                | Value | Description                                             | aad   | salt  | party | epk   | s-key | s-kid | comments          |
|---------------------|-------|---------------------------------------------------------|-------| ------|-------|-------|-------|-------|-------------------|
| ES256               | -7    | ECDSA w/ SHA-256                                        |       |       |       |       |       |       | kty:EC            |
| ES384               | -35   | ECDSA w/ SHA-384                                        |       |       |       |       |       |       | kty:EC            |
| ES512               | -36   | ECDSA w/ SHA-512                                        |       |       |       |       |       |       | kty:EC            |
| EdDSA               | -8    | EdDSA                                                   |       |       |       |       |       |       | kty:OKP           |
| HMAC 256/64         | 4     | HMAC w/ SHA-256 truncated to 64 bits                    |       |       |       |       |       |       |                   |
| HMAC 256/256        | 5     | HMAC w/ SHA-256                                         |       |       |       |       |       |       |                   |
| HMAC 384/384        | 6     | HMAC w/ SHA-384                                         |       |       |       |       |       |       |                   |
| HMAC 512/512        | 7     | HMAC w/ SHA-512                                         |       |       |       |       |       |       |                   |
| AES-MAC 128/64      | 14    | AES-MAC 128-bit key, 64-bit tag                         |       |       |       |       |       |       |                   |
| AES-MAC 256/64      | 15    | AES-MAC 256-bit key, 64-bit tag                         |       |       |       |       |       |       |                   |
| AES-MAC 128/128     | 25    | AES-MAC 128-bit key, 128-bit tag                        |       |       |       |       |       |       |                   |
| AES-MAC 256/128     | 26    | AES-MAC 256-bit key, 128-bit tag                        |       |       |       |       |       |       |                   |
| A128GCM             | 1     | AES-GCM mode w/ 128-bit key, 128-bit tag                |   o   |       |       |       |       |       |                   |
| A192GCM             | 2     | AES-GCM mode w/ 192-bit key, 128-bit tag                |   o   |       |       |       |       |       |                   |
| A256GCM             | 3     | AES-GCM mode w/ 256-bit key, 128-bit tag                |   o   |       |       |       |       |       |                   |
| AES-CCM-16-64-128   | 10    | AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce     |   o   |       |       |       |       |       |                   |
| AES-CCM-16-64-256   | 11    | AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce     |   o   |       |       |       |       |       |                   |
| AES-CCM-64-64-128   | 12    | AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce      |   o   |       |       |       |       |       |                   |
| AES-CCM-64-64-256   | 13    | AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce      |   o   |       |       |       |       |       |                   |
| AES-CCM-16-128-128  | 30    | AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce    |   o   |       |       |       |       |       |                   |
| AES-CCM-16-128-256  | 31    | AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce    |   o   |       |       |       |       |       |                   |
| AES-CCM-64-128-128  | 32    | AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce     |   o   |       |       |       |       |       |                   |
| AES-CCM-64-128-256  | 33    | AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce     |   o   |       |       |       |       |       |                   |
| ChaCha20/Poly1305   | 24    | ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag           |       |       |       |       |       |       | nonce wo counter  |
| direct              | -6    | Direct use of CEK                                       |       |       |       |       |       |       | kty:oct(symm)     |
| direct+HKDF-SHA-256 | -10   | Shared secret w/ HKDF and SHA-256                       |       |   o   |   o   |       |       |       |                   |
| direct+HKDF-SHA-512 | -11   | Shared secret w/ HKDF and SHA-512                       |       |   o   |   o   |       |       |       |                   |
| direct+HKDF-AES-128 | -12   | Shared secret w/ AES-MAC 128-bit key                    |       |   o   |   o   |       |       |       |                   |
| direct+HKDF-AES-256 | -13   | Shared secret w/ AES-MAC 256-bit key                    |       |   o   |   o   |       |       |       |                   |
| A128KW              | -3    | AES Key Wrap w/ 128-bit key                             |       |       |       |       |       |       |                   |
| A192KW              | -4    | AES Key Wrap w/ 192-bit key                             |       |       |       |       |       |       |                   |
| A256KW              | -5    | AES Key Wrap w/ 256-bit key                             |       |       |       |       |       |       |                   |
| ECDH-ES + HKDF-256  | -25   | ECDH ES w/ HKDF - SHA-256                               |       |   o   |   o   |   o   |       |       |                   |
| ECDH-ES + HKDF-512  | -26   | ECDH ES w/ HKDF - SHA-512                               |       |   o   |   o   |   o   |       |       |                   |
| ECDH-SS + HKDF-256  | -27   | ECDH SS w/ HKDF - SHA-256                               |       |   o   |   o   |       |   o   |   o   |                   |
| ECDH-SS + HKDF-512  | -28   | ECDH SS w/ HKDF - SHA-512                               |       |   o   |   o   |       |   o   |   o   |                   |
| ECDH-ES + A128KW    | -29   | ECDH ES w/ HKDF - SHA-256 A128KW                        |       |   o   |   o   |   o   |       |       |                   |
| ECDH-ES + A192KW    | -30   | ECDH ES w/ HKDF - SHA-256 A192KW                        |       |   o   |   o   |   o   |       |       |                   |
| ECDH-ES + A256KW    | -31   | ECDH ES w/ HKDF - SHA-256 A128KW                        |       |   o   |   o   |   o   |       |       |                   |
| ECDH-SS + A128KW    | -32   | ECDH SS w/ HKDF - SHA-256 A128KW                        |       |   o   |   o   |       |   o   |   o   |                   |
| ECDH-SS + A192KW    | -33   | ECDH SS w/ HKDF - SHA-256 A192KW                        |       |   o   |   o   |       |   o   |   o   |                   |
| ECDH-SS + A256KW    | -34   | ECDH SS w/ HKDF - SHA-256 A128KW                        |       |   o   |   o   |       |   o   |   o   |                   |
