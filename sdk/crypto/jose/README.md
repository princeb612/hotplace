## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# JOSE — JSON Object Signing and Encryption

## 1. Role

`sdk/crypto/jose` (without the leading space) implements the JSON Object Signing and Encryption family: JWS, JWE, JWK and JWA. It bridges JSON-oriented representations and the common cryptographic operation layer; it is not a separate implementation of RSA, ECDSA, HMAC, AES or key storage.

## 2. Model

The module is organized around a shared context and focused processing classes:

- `json_object_signing` — JWS signing and verification.
- `json_object_encryption` — JWE key management and content encryption/decryption.
- `json_object_signing_encryption` — shared context lifecycle and high-level orchestration.
- `json_web_key` — JWK parsing/writing and conversion to `crypto_key`.
- `json_web_signature` — JWS-oriented signature helper.
- `types.hpp` — JOSE identifiers, context, recipient, encryption and signature state.

Detailed records: [object model and context](jose-object-model.md), [JWS signing and JWE encryption](jose-signing-encryption.md), and [JWK and algorithm mapping](jose-key-and-algorithms.md).

## 3. Important behavior and lifetime

The protocol layer constructs the JOSE signing input or encryption parameters and chooses the JOSE serialization. The underlying cryptographic operation is delegated to `sdk/crypto/basic`. JWE key management and content encryption are separate stages; for multiple recipients, recipient-specific key-management data is associated with the shared content-encryption result.

The older implementation-status tables and explicit TODO list are retained in [JOSE overview](jose-overview.md) for maintainer review; their checkboxes should be treated as historical notes, not as a freshly audited status matrix.

## 4. Example from the source tests

The RFC 7515 testcase includes the RFC A.1 HS256 example. It signs and verifies a payload in compact, flattened JSON, and general JSON serialization forms. The RFC 7520 test group also exercises JWS/JWE examples; see [the testcase map](../../../test/testcase/jose/testcase_jose.md).

## 5. Relationships

- `../basic/` supplies cryptographic primitives and key operations.
- `../advisor/` supplies common cryptographic metadata and identifier mapping.
- `../cose/` is the CBOR-oriented security-object layer; JOSE instead uses JSON-oriented objects.
- `../../../io/cbor/` provides CBOR support used by COSE, while JOSE consumes JSON representations.
- `../../../test/testcase/jose/` contains the direct test sources and vectors.

## 6. References

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7516 — JSON Web Encryption (JWE)
- RFC 7517 — JSON Web Key (JWK)
- RFC 7518 — JSON Web Algorithms (JWA)
- RFC 7520 — Examples of Protecting Content Using JOSE
- RFC 7638 — JSON Web Key (JWK) Thumbprint
- RFC 8037 — CFRG ECDH and Signatures in JOSE
