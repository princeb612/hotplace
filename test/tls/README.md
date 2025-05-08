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

### test_construct_tls_routine

- https://tls13.xargs.org
  - C->S client_hello
  - S->C server_hello
  - S->C change_cipher_spec
  - S->C encrypted_extensions
  - S->C certificate
  - S->C certificate_verify
  - S->C finished
  - C->S change_cipher_spec
  - C->S finished
- https://tls12.xargs.org
  - C->S client_hello
  - S->C server_hello
  - S->C certificate
  - S->C server_key_exchange
  - S->C server_hello_done
  - C->S client_key_exchange
  - C->S change_cipher_spec
  - C->S finished
  - S->C change_cipher_spec
  - S->C finished
- TLS 1.3
  - openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -tls1_3
  - openssl s_client -connect localhost:9000 -state -debug -tls1_3
  - C->S client_hello
  - S->C server_hello
  - S->C change_cipher_spec
  - S->C encrypted_extensions
  - S->C certificate
  - S->C certificate_verify
  - S->C finished
  - C->S finished
  - S->C new_session_ticket
- TLS 1.2
  - openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -no_tls1_3
  - openssl s_client -connect localhost:9000 -state -debug -tls1_2
  - C->S client_hello
  - S->C server_hello
  - S->C certificate
  - S->C server_key_exchange
  - S->C server_hello_done
  - C->S client_key_exchange
  - C->S change_cipher_spec
  - C->S finished
  - S->C new_session_ticket
  - S->C change_cipher_spec
  - S->C finished
- DTLS 1.2
  - openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -dtls
  - openssl s_client -connect localhost:9000 -state -debug -dtls
  - C->S client_hello
  - S->C hello_verify_request
  - C->S client_hello
  - S->C server_hello
  - S->C certificate
  - S->C server_key_exchange
  - S->C server_hello_done
  - C->S client_key_exchange
  - C->S change_cipher_spec
  - C->S finished
  - S->C new_session_ticket
  - S->C change_cipher_spec
  - S->C finished

### packet capture

* [tls13](tls13/README.md)
* [tls12](tls12/README.md)
* [dtls12](dtls12/README.md)

### TLS 1.3

* 1-RTT
  * C->S
    * client_hello
  * S->C
    * server_hello
    * encrypted_extensions
    * certificate
    * certificate_verify
    * finished
  * C->S
    * finished
  * S->C
    * new_session_ticket
  * C->S
    * application data
  * S->C
    * application data
  * C->S
    * close_notify
  * S->C
    * close_notify
* 0-RTT
  * C->S
    * client_hello
      * pre_shared_key
  * S->C
    * server_hello
    * encrypted_extensions
    * finished
