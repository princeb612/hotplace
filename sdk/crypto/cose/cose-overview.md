# Developer Notes — COSE Algorithm Inventory

## Purpose and current-status boundary

This note preserves the compact COSE message-shape and algorithm-identifier inventory. For the detailed CBOR-to-COSE processing flow and the source/test-based algorithm-family summary, see [COSE README](README.md). The table below is a developer-maintained inventory, not a blanket guarantee of runtime support across OpenSSL/provider builds.

## Message shapes and historical inventory
### message

````
                       protected  unprotected      payload     singleitem/multiitems
                       [0]        [1]              [2]         [3]             [4]
 cbor_tag_t::encrypt   protected, unprotected_map, ciphertext, [+recipient]
 cbor_tag_t::encrypt0  protected, unprotected_map, ciphertext
 cbor_tag_t::mac       protected, unprotected_map, payload,    tag,            [+recipient]
 cbor_tag_t::mac0      protected, unprotected_map, payload,    tag
 cbor_tag_t::sign      protected, unprotected_map, payload,    [+signature]
 cbor_tag_t::sign1     protected, unprotected_map, payload,    signature
````

### algorithm

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
| O | ECDH-ES + A256KW    | -31   | ECDH ES w/ HKDF - SHA-256 A256KW                     |   | o | o | o |   |   |                  |
| O | ECDH-SS + A128KW    | -32   | ECDH SS w/ HKDF - SHA-256 A128KW                     |   | o | o |   | o | o |                  |
| O | ECDH-SS + A192KW    | -33   | ECDH SS w/ HKDF - SHA-256 A192KW                     |   | o | o |   | o | o |                  |
| O | ECDH-SS + A256KW    | -34   | ECDH SS w/ HKDF - SHA-256 A256KW                     |   | o | o |   | o | o |                  |

## ChaCha20/Poly1305 implementation status

COSE ChaCha20/Poly1305 (algorithm ID 24) is currently unsupported by hotplace's COSE encryption path. The implementation attempt exposed differences in ChaCha20 state and counter/nonce layout between the OpenSSL implementation examined and the libsodium APIs, including the original and IETF variants. The current code therefore returns `not_supported`, and an isolated testcase records this expected result.

This is a limitation of hotplace's current integration, not a statement that OpenSSL itself lacks ChaCha20-Poly1305 support. The libsodium API comparison is implementation research; it does not imply that hotplace currently uses libsodium for this COSE operation.

## Interpretation notes
The X mark for ChaCha20/Poly1305 corresponds to the current resource group's explicit `cose_hint_not_supported` flag. The table's O marks record the inventory's implementation intent; confirm the current resource table, testcase arrays and active backend before treating any algorithm as available. The current source includes algorithm metadata for families beyond this older table, including RSA signature/key-management and ML-DSA entries; the README's inventory summarizes those separately.
