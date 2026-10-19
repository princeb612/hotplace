## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# JOSE testcase coverage map

## 1. Role

This document maps the JOSE testcase sources to the protocol behaviors and fixture families they exercise. It complements the directory index rather than duplicating every fixture filename.

## 2. Test model

The tests combine known RFC examples, explicit operation-result assertions, serialization checks, JWK conversion, and algorithm-specific probes. Source assertions and report status are separate evidence: the presence of a test function describes intended coverage, while the report records what ran in the supplied environment.

## 3. Example: JWS known-output verification

In `testcase_rfc7515.cpp::test_rfc7515_A1()`, the test loads the symmetric JWK, signs a known header and payload, and compares the generated compact JWS to the RFC's expected string. It then signs/verifies flattened and general JSON representations. This checks both cryptographic output and serialization behavior.

## 4. Test and verification status

### 4.1 Source-level coverage

| Source file | Named functions / focus | Main fixtures or data |
|---|---|---|
| `testcase_rfc7515.cpp` | `test_basic`, `test_rfc7515_A1`–`A7`, `test_rfc7515_HS`, key-generation and PEM paths | RFC 7515 JWK/PEM data |
| `testcase_rfc7516.cpp` | `test_rfc7516_A1`–`A4`, `test_rfc7516_B`, JWE example handling | RFC 7516 JWK/JWS fixtures |
| `testcase_rfc7517.cpp` | `test_jwk` / JWK handling | JWK fixtures |
| `testcase_rfc7518.cpp` | `test_rfc7518_C`, `test_rfc7518_RSASSA_PSS`, RSA-OAEP variants | RFC 7518 Alice/Bob JWKs |
| `testcase_rfc7520.cpp` | `test_rfc7520_features`, `test_rfc7520_signature`, `test_rfc7520_jwe`, nesting/signature/encryption | RFC 7520 `.jws`, `.jwe`, `.jwk` files |
| `testcase_rfc7638.cpp` | `test_jwk_thumbprint` | `rfc7638_3.jwk` |
| `testcase_rfc8037.cpp` | `test_rfc8037_features`, ECDH/OKP cases | X25519, X448, Ed25519 JWKs |
| `testcase_akp.cpp` | `test_akp` — ML-DSA sign/verify | ML-DSA-44/65/87 JSON vectors |
| `testvector_akp.cpp` | `test_json_testvector_akp` | AKP JSON vectors |

The directory also contains `sample.cpp/.hpp`, `CMakeLists.txt`, a general `keys.jwk`, and RFC 7520 fixtures that cover both JWS and JWE. The OpenSSL 3.5 guard in `testcase_akp.cpp` is part of the source-level behavior and should not be mistaken for unconditional ML-DSA availability.

### 4.2 Documentation and verification status

The supplied report snapshot identifies the JOSE suite as MinGW64 / source revision 1104. It reports **295 pass, 0 expt, 0 fail, 0 skip, 2 triv**. Per-group summaries include RFC 7515: 34 success and 2 triv; RFC 7520: 164 success; RFC 8037: 30 success; AKP: 18 success. These labels are reproduced as printed; no framework meaning is inferred for `triv` or `expt`. No tests were rerun during this documentation pass.

## 5. Relationships

- `../../../sdk/crypto/jose/` — production implementation.
- `../../../sdk/crypto/basic/` — common cryptographic operations and keys.
- `../../../sdk/crypto/advisor/` — JOSE algorithm metadata and shared mappings.
- `../../../sdk/crypto/cose/` — related CBOR/COSE security-object layer.

## 6. References

- [JOSE directory overview](../../../sdk/crypto/jose/README.md)
- [JWS and JWE processing](../../../sdk/crypto/jose/jose-signing-encryption.md)
- [JWK and algorithm mapping](../../../sdk/crypto/jose/jose-key-and-algorithms.md)
- RFC 7515, RFC 7516, RFC 7517, RFC 7518, RFC 7520, RFC 7638, RFC 8037
