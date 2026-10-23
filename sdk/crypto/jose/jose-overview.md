## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Developer Notes - Historical JOSE Implementation Status

## Purpose and status boundary

This is a preserved developer-maintenance note, not a current support guarantee. Its tables record an older status snapshot and have not all been re-audited. The old unchecked checklist is tracked separately from this historical reference. For the current source-based mapping inventory and the distinction between metadata, test coverage and runtime availability, use the [JOSE README](README.md).

## Historical algorithm-status tables
The legacy tables below enumerate status for JWS signature/MAC algorithms, JWE key management, JWE content encryption, and JWK key types. Use the focused records for the architectural model: [object model](jose-object-model.md), [JWS/JWE flow](jose-signing-encryption.md), and [JWK/algorithm mapping](jose-key-and-algorithms.md).

# Cryptographic Algorithms for Digital Signatures and MACs

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

## Interpretation notes
These tables are a snapshot from the existing document, not a normative declaration of current backend support. Actual behavior also depends on provider/build configuration and key availability. The presence of source tests is useful evidence but does not by itself establish support in every build environment.

## 4. Relationships
### Implementation and test sources


### Source-test evidence

The direct source-level examples are mapped in [`testcase_jose.md`](../../../test/testcase/jose/testcase_jose.md). In particular, RFC 7515 tests exercise signature/MAC operations, RFC 7516 and RFC 7520 tests exercise encryption and key management, and RFC 7638/8037/AKP sources cover thumbprints and additional key/algorithm families.

- [JWS signing and JWE encryption](jose-signing-encryption.md)
- [JWK and algorithm mapping](jose-key-and-algorithms.md)
- [JOSE object model and context](jose-object-model.md)

## 5. References
- RFC 7515 — JSON Web Signature (JWS).
- RFC 7516 — JSON Web Encryption (JWE).
- RFC 7517 — JSON Web Key (JWK).
- RFC 7518 — JSON Web Algorithms (JWA).
- RFC 7520 — Examples of Protecting Content Using JOSE.
- RFC 7638 — JSON Web Key (JWK) Thumbprint.
- RFC 8037 — CFRG Elliptic Curve Diffie-Hellman and Signatures in JOSE.

## Development Notes (for maintainer review)

The older status matrix is preserved as historical material, not as a verified statement of current support. Earlier unchecked items included thumbprints and post-quantum work; the current source includes an RFC 7638 thumbprint testcase and an AKP/ML-DSA testcase. Presence of a testcase does not establish broad interoperability or runtime availability in every build.
