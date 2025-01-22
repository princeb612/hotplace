## test

### study progress

- [ ] encryption
  - [ ] encryption by cipher mode (not by TLS version)
- [ ] TLS version
  - [x] TLS1.3
  - [ ] TLS1.2
- [v] verification
  - [x] certificate verify
  - [x] finished
  - [x] pre shared key (psk binder)

### Cipher Suites

| Cipher Suites                                 | TLS1.3 | TLS 1.2 |
| --                                            |   --   |   --    |
| TLS_AES_256_GCM_SHA384                        |   P    |         |
| TLS_CHACHA20_POLY1305_SHA256                  |   P    |         |
| TLS_AES_128_GCM_SHA256                        |   P    |         |
| TLS_AES_128_CCM_8_SHA256                      |   P    |         |
| TLS_AES_128_CCM_SHA256                        |   P    |         |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       |   P    |         |
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       |   P    |         |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         |   P    |         |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         |   P    |         |
| TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256      |   P    |         |
| TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384      |   P    |         |
| TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256        |   P    |         |
| TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384        |   P    |         |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM              |   P    |         |
| TLS_ECDHE_ECDSA_WITH_AES_256_CCM              |   P    |         |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            |   P    |         |
| TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            |   P    |         |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   |   P    |         |
| TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 |   P    |         |
