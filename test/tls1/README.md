## test

### Cipher Suites

| code   | version | Cipher Suites                                 |        |
| --     | --      | --                                            | --     |
| 0x1301 | TLS 1.3 | TLS_AES_128_GCM_SHA256                        | tested |
| 0x1302 | TLS 1.3 | TLS_AES_256_GCM_SHA384                        | tested |
| 0x1303 | TLS 1.3 | TLS_CHACHA20_POLY1305_SHA256                  | tested |
| 0x1304 | TLS 1.3 | TLS_AES_128_CCM_SHA256                        | tested |
| 0x1305 | TLS 1.3 | TLS_AES_128_CCM_8_SHA256                      | tested |
| 0xc027 | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         | tested |
| 0xc028 | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384         | tested |
| 0xc02b | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | tested |
| 0xc02c | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | tested |
| 0xc05c | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256      | tested |
| 0xc05d | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384      | tested |
| 0xc0ac | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_CCM              | tested |
| 0xc0ad | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_CCM              | tested |
| 0xc0ae | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            | tested |
| 0xc0af | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            | tested |
| 0xcca9 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | tested |
| 0xc023 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       | tested |
| 0xc024 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       | tested |
| 0xc02f | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | tested |
| 0xc030 | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | tested |
| 0xc05c | TLS 1.2 | TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256        | tested |
| 0xc05d | TLS 1.2 | TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384        | tested |
| 0xc072 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  | tested |
| 0xc073 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  | tested |
| 0xc076 | TLS 1.2 | TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256    | tested |
| 0xc077 | TLS 1.2 | TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384    | tested |
| 0xcca8 | TLS 1.2 | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | tested |

### study

#### why gmt_unix_time still 4 bytes

- time_t
  - 1970.01.01 00:00:00 UTC~
  - sizeof(time_t) = 8
- TLS client_hello::random begins 00000000
  - RFC 5246 7.4.1.2.  Client Hello
    - uint32 gmt_unix_time;
    - opaque random_bytes[28];
  - 1970.01.01 00:00:00 UTC~2038.01.19 03:14:07 UTC (signed int time_t)
    - cat(hton64(time(nullptr)), sizeof(uint32)) || PRNG_random(28 bytes)
    - 00000000 || random
