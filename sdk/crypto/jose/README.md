# JOSE

`sdk/crypto/jose` implements the JSON Object Signing and Encryption family around JWS, JWE, JWK and JWA.

The module sits between JSON/HTTP-oriented representations and `sdk/crypto/basic`: JOSE defines the serialization, algorithm identifiers, key representation, protected headers and cryptographic processing, while the underlying cryptographic primitives are supplied by the common crypto layer.

## Implementation map

- `json_object_signing` — JWS signing and verification.
- `json_object_encryption` — JWE encryption and decryption, including key-management algorithms and content encryption.
- `json_object_signing_encryption` — shared JOSE context and orchestration for signing/encryption operations.
- `json_web_key` — JWK parsing/writing and conversion to `crypto_key`.
- `json_web_signature` — JWS-oriented signature processing helper.
- `types.hpp` — JOSE context, recipient, encryption and signature state.

## Detailed records

- [JOSE object model and context](jose-object-model.md)
- [JWS signing and JWE encryption](jose-signing-encryption.md)
- [JWK and algorithm mapping](jose-key-and-algorithms.md)

## Related areas

- `../basic/` — cryptographic primitives, keys, MAC, KDF and signatures.
- `../advisor/` — algorithm/resource metadata and identifier mapping.
- `../../io/string/` — URL/string helpers used around JSON/HTTP-oriented processing.
- `../../io/cbor/` and `../cose/` — analogous CBOR/COSE processing layer.

## Tests

- `test/testcase/jose/`
  - RFC 7515 JWS
  - RFC 7516 JWE
  - RFC 7517 JWK
  - RFC 7518 JWA
  - RFC 7520 JOSE examples
  - RFC 7638 JWK thumbprints
  - RFC 8037 ECDH/EdDSA
  - AKP / ML-DSA vectors

The large RFC 7520 fixture set is an important part of the module's practical coverage.

## References

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7516 — JSON Web Encryption (JWE)
- RFC 7517 — JSON Web Key (JWK)
- RFC 7518 — JSON Web Algorithms (JWA)
- RFC 7520 — Examples of Protecting Content Using JOSE
- RFC 7638 — JWK Thumbprint
- RFC 8037 — CFRG ECDH and Signatures in JOSE
