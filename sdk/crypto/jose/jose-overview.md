## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# JSON Object Signing and Encryption (JOSE) implementation status

## 1. Role

This page preserves the module's pre-existing algorithm-status reference. Unlike the other JOSE records, it is a status-table/history document; the check marks are retained as written and have not been independently re-audited during this documentation pass.

## 2. Model

The legacy tables below enumerate status for JWS signature/MAC algorithms, JWE key management, JWE content encryption, and JWK key types. Use the focused records for the architectural model: [object model](jose-object-model.md), [JWS/JWE flow](jose-signing-encryption.md), and [JWK/algorithm mapping](jose-key-and-algorithms.md).

# JSON Object Signing and Encryption (JOSE) implementation status

## Cryptographic Algorithms for Digital Signatures and MACs

| Implemented  | "alg" Param Value | Digital Signature or MAC Algorithm | Implementation Requirements |
|-- |--     |--                                              |--            |
| O | HS256 | HMAC using SHA-256                             | Required     |
| O | HS384 | HMAC using SHA-384                             | Optional     |
| O | HS512 | HMAC using SHA-512                             | Optional     |
| O | RS256 | RSASSA-PKCS1-v1_5 using SHA-256                | Recommended  |
| O | RS384 | RSASSA-PKCS1-v1_5 using SHA-384                | Optional     |
| O | RS512 | RSASSA-PKCS1-v1_5 using SHA-512                | Optional     |
| O | ES256 | ECDSA using P-256 and SHA-256                  | Recommended+ |
| O | ES384 | ECDSA using P-384 and SHA-384                  | Optional     |
| O | ES512 | ECDSA using P-521 and SHA-512                  | Optional     |
| O | PS256 | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | Optional     |
| O | PS384 | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | Optional     |
| O | PS512 | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | Optional     |
| - | none  | No digital signature or MAC performed          | Optional     |
| O | EdDSA | RFC 8037                                       |              |

## Cryptographic Algorithms for Key Management

| Implemented  | "alg" Param Value  | Key Management Algorithm | More Header Params  | Implementation Requirements |
|-- |--                  |--                                                         |--      |--              |
| O | RSA1_5             | RSAES-PKCS1-v1_5                                          | (none) | Recommended-   |
| O | RSA-OAEP           | RSAES OAEP using default parameters                       | (none) | Recommended+   |
| O | RSA-OAEP-256       | RSAES OAEP using SHA-256 and MGF1 with SHA-256            | (none) | Optional       |
| O | A128KW             | AES Key Wrap with default initial value using 128-bit key | (none) | Recommended    |
| O | A192KW             | AES Key Wrap with default initial value using 192-bit key | (none) | Optional       |
| O | A256KW             | AES Key Wrap with default initial value using 256-bit key | (none) | Recommended    |
| O | dir                | Direct use of a shared symmetric key as the CEK           | (none) | Recommended    |
| O | ECDH-ES            | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF | "epk","apu","apv" | Recommended+ |
| O | ECDH-ES|A128KW     | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"    | "epk","apu","apv" | Recommended    |
| O | ECDH-ES|A192KW     | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"    | "epk","apu","apv" | Optional       |
| O | ECDH-ES|A256KW     | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"    | "epk","apu","apv" | Recommended    |
| O | A128GCMKW          | Key wrapping with AES GCM using 128-bit key               | "iv","tag"        | Optional       |
| O | A192GCMKW          | Key wrapping with AES GCM using 192-bit key               | "iv","tag"        | Optional       |
| O | A256GCMKW          | Key wrapping with AES GCM using 256-bit key               | "iv","tag"        | Optional       |
| O | PBES2-HS256|A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping             | "p2s","p2c"       | Optional       |
| O | PBES2-HS384|A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping             | "p2s","p2c"       | Optional       |
| O | PBES2-HS512|A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping             | "p2s","p2c"       | Optional       |

## Cryptographic Algorithms for Content Encryption

| Implemented  | "enc" Param Value  | Content Encryption Algorithm | Implementation Requirements |
|-- |--             |--                         |--             |
| O | A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in Section 5.2.3 | Required |
| O | A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in Section 5.2.4 | Optional |
| O | A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in Section 5.2.5 | Required |
| O | A128GCM       | AES GCM using 128-bit key | Recommended   |
| O | A192GCM       | AES GCM using 192-bit key | Optional      |
| O | A256GCM       | AES GCM using 256-bit key | Recommended   |

## JWK

| Implemented | kty |                |   |
|-- |--     |--                      |-- |
| O | oct   | JWK/PEM(openssl 1.1.1) |   |
| O | RSA   | JWK/PEM                |   |
| O | EC    | JWK/PEM                | crv "P-256","P-384","P-521" |
| O | OKP   | JWK/PEM                | crv "Ed25519","Ed448","X25519","X448" |

## 3. Important behavior and lifetime

These tables are a snapshot from the existing document, not a normative declaration of current backend support. Actual behavior also depends on provider/build configuration and key availability. The presence of source tests is useful evidence but does not by itself establish support in every build environment.

## 4. Example from the source tests

The direct source-level examples are mapped in [`testcase_jose.md`](../../../test/testcase/jose/testcase_jose.md). In particular, RFC 7515 tests exercise signature/MAC operations, RFC 7516 and RFC 7520 tests exercise encryption and key management, and RFC 7638/8037/AKP sources cover thumbprints and additional key/algorithm families.

## 5. Relationships

- [JWS signing and JWE encryption](jose-signing-encryption.md)
- [JWK and algorithm mapping](jose-key-and-algorithms.md)
- [JOSE object model and context](jose-object-model.md)

## 6. References

- RFC 7515, RFC 7516, RFC 7517, RFC 7518, RFC 7520, RFC 7638, RFC 8037
- Existing JSON parser benchmark links retained from the source note.
## Development Notes (for maintainer review)

The source document's explicit TODO checklist and the older status matrix are preserved below. They are historical maintainer notes, not a verified statement that each item is still outstanding. For example, RFC 7638 test coverage and AKP/ML-DSA test vectors are present in this source tree even though the older checklist still mentions JWK thumbprints and post-quantum work.

## TODO

- [ ] disable RSA1_5
- [ ] JWK SHA-256 Thumbprint
- [ ] draft-ietf-jose-fully-post-quantum-03
- [ ] draft-prorock-cose-post-quantum-key-agreement
- [ ] enc (Edwards-curve)
