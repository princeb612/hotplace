## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1106                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1106                  │
│ — testcase coverage map                      │
└──────────────────────────────────────────────┘
```

# JOSE testcase coverage map

## 1. What

This document is a source-oriented index of JOSE testcase functions and fixture families. The directory [README](README.md) contains the reproducible procedures and the detailed distinction between explicit output comparisons, operation-status checks and diagnostic output.

## 2. How

1. Use this map when tracing a testcase from the executable dispatch to its implementation and fixture.

1. Start at `sample.cpp`: it calls the RFC groups in order—7515, 7516, 7517, 7518, 7520, 7638, 8037—then the common AKP test and JSON-vector consumer.
2. Follow the function names below to locate the specific protocol path.
3. Follow the fixture names to distinguish static RFC inputs from values generated during a test.
4. Check the matching assertions in the source before treating a test as a fixed known-answer comparison. A helper's successful return status may not assert plaintext equality or the verification-result boolean.
5. Use the runtime report only as evidence for the supplied run context; the source list itself does not prove that a path executed in that run.

2. Example: `test_rfc7515_A1()` loads `rfc7515.jwk`, signs a fixed header and payload with HS256, and compares the compact JWS string with the RFC output. It also exercises flattened and general JSON serialization, but those paths primarily record sign/verify operation status. This is a stronger output oracle for the compact form than a status-only check.

## 3. Evidence

### Source-level coverage

| Source file | Functions / focus | Main fixtures or data |
|---|---|---|
| `testcase_rfc7515.cpp` | `test_basic`, `test_rfc7515_A1`–`A7`, `test_rfc7515_HS`, PEM/key-generation paths, key-match cases | `rfc7515.jwk`, `rfc7515.pem`, RFC 7515 fixed strings |
| `testcase_rfc7516.cpp` | JWE A.1–A.4, RSA-OAEP variants, JWK helper, Appendix B CBC-HMAC computation | `rfc7516_A*.jwk/.jws`, embedded RFC CEK/IV/AAD/ciphertext/tag values |
| `testcase_rfc7517.cpp` | RFC 7517 Appendix C encrypted-private-key example | `rfc7517_C.jwk`, fixed passphrase |
| `testcase_rfc7518.cpp` | PS256 serialization, bidirectional P-384 ECDH, RFC Appendix C Concat KDF | `rfc7518_C_alice.jwk`, `rfc7518_C_bob.jwk` |
| `testcase_rfc7520.cpp` | Fixture JWS verification, fixture JWE decryption, nested JWS/JWE, generated flattened/general JWE matrices | `rfc7520_figure*.jws/.jwe`, `rfc7520_priv.jwk`, `rfc7520_pub.jwk`, password-based key fixture |
| `testcase_rfc7638.cpp` | Canonical RSA public JWK JSON, SHA-256 and thumbprint comparison | `rfc7638_3.jwk`, expected thumbprint |
| `testcase_rfc8037.cpp` | Ed25519 JWS, X25519/X448 ECDH-ES, generated OKP JWE/JWS matrix | `rfc8037_A_X25519.jwk`, `rfc8037_A_X448.jwk`, `rfc8037_A_ed25519.jwk` |
| `testcase_akp.cpp` | ML-DSA-44/65/87 JWS sign/verify | Generated keys and a fixed payload |
| `testvector_akp.cpp` | Load JWK from JSON, compare raw public key, verify supplied JWS | `testvector_akp_mldsa44.json`, `...65.json`, `...87.json` |

The directory also contains `sample.cpp/.hpp`, `CMakeLists.txt`, `keys.jwk`, and the RFC 7520 JWS/JWE fixture family. `CMakeLists.txt` copies `*.json`, `*.jwe`, `*.jwk`, `*.jws` and `*.pem` files into the build tree for the testcase executable.

The ML-DSA source paths are guarded by OpenSSL 3.5 or later. On older versions, the source records `not_supported`; this should not be reported as a successful ML-DSA run.

### Documentation and verification status

The supplied report snapshot identifies the JOSE suite as MinGW64 / source revision 1104. It reports **295 pass, 0 expt, 0 fail, 0 skip, 2 triv**. Per-group summaries include RFC 7515: 34 success and 2 triv; RFC 7520: 164 success; RFC 8037: 30 success; AKP: 18 success. These labels are reproduced as printed; no framework meaning is inferred for `triv` or `expt`. No tests were rerun during this documentation pass.

## 4. Relationships

- [Directory procedures and evidence distinctions](README.md)
- [JOSE implementation overview](../../../sdk/crypto/jose/jose-overview.md)
- [JWS/JWE processing](../../../sdk/crypto/jose/jose-signing-encryption.md)
- [JWK and algorithm mapping](../../../sdk/crypto/jose/jose-key-and-algorithms.md)
- [Shared crypto primitives and keys](../../../sdk/crypto/basic/README.md)

## 5. References

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7516 — JSON Web Encryption (JWE)
- RFC 7517 — JSON Web Key (JWK)
- RFC 7518 — JSON Web Algorithms (JWA)
- RFC 7520 — Examples of Protecting Content Using JOSE
- RFC 7638 — JSON Web Key (JWK) Thumbprint
- RFC 8037 — CFRG Elliptic Curve Diffie-Hellman and Signatures in JOSE
