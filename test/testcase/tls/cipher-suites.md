# Developer Notes - TLS cipher-suite inventory

This table preserves the cipher-suite identifiers represented in the existing TLS test notes. It is an inventory, not a guarantee that every row has a dedicated YAML vector, is exercised in every environment, or has been re-run at the current source revision.

| Code | Protocol | Cipher suite | Source/vector note |
|---|---|---|---|
| 0x1301 | TLS 1.3 | TLS_AES_128_GCM_SHA256 | Listed in TLS 1.3 capture set |
| 0x1302 | TLS 1.3 | TLS_AES_256_GCM_SHA384 | Listed in TLS 1.3 capture set |
| 0x1303 | TLS 1.3 | TLS_CHACHA20_POLY1305_SHA256 | Listed in TLS 1.3 capture set |
| 0x1304 | TLS 1.3 | TLS_AES_128_CCM_SHA256 | Listed in TLS 1.3 capture set |
| 0x1305 | TLS 1.3 | TLS_AES_128_CCM_8_SHA256 | Inventory entry only; verify current vector/test source before claiming coverage |
| 0xc023 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 | Listed |
| 0xc024 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 | Listed |
| 0xc027 | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 | Listed |
| 0xc028 | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 | Listed |
| 0xc02b | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | TLS 1.2 capture exists |
| 0xc02c | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | TLS 1.2 capture exists |
| 0xc02f | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Listed |
| 0xc030 | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | Listed |
| 0xc05c | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 | Listed |
| 0xc05d | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 | Listed |
| 0xc060 | TLS 1.2 | TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 | Listed |
| 0xc061 | TLS 1.2 | TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 | Listed |
| 0xc072 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 | Listed |
| 0xc073 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 | Listed |
| 0xc076 | TLS 1.2 | TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 | Listed |
| 0xc077 | TLS 1.2 | TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 | Listed |
| 0xcca8 | TLS 1.2 | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | TLS 1.2 capture exists |
| 0xcca9 | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | TLS 1.2 capture exists |
| 0xc0ac | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_CCM | Listed |
| 0xc0ad | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_CCM | Listed |
| 0xc0ae | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 | No coverage claim recorded here |
| 0xc0af | TLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 | No coverage claim recorded here |

## How to read this inventory

- A capture filename documents one recorded negotiation and its associated trace; it is not the same thing as an automated unit assertion.
- The [TLS 1.2 capture index](tls12/README.md) and [TLS 1.3 capture index](tls13/README.md) link the currently stored PCAPs and peer notes.
- The [top-level TLS README](README.md) documents the executable YAML replay path. The current `test.md` checklist records CCM8 as lacking a test vector, so the presence of a suite identifier in this table must not be interpreted as contrary evidence.
- Recheck the relevant source, YAML vectors, and execution report before changing an inventory note to a positive test-coverage claim.
