## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# JWK and JOSE algorithm mapping

## 1. Role

This record describes the boundary between JSON Web Key (JWK) material, JOSE algorithm identifiers, and hotplace's common crypto/key abstractions.

## 2. Model

`json_web_key` bridges JWK JSON and `crypto_key`. The source's existing status table lists these key types:

- `oct` — symmetric keys
- `RSA`
- `EC` — P-256, P-384 and P-521
- `OKP` — Ed25519, Ed448, X25519 and X448

`types.hpp` groups algorithm identifiers by protocol role: `jws_t` for JWS signature/MAC algorithms, `jwa_t` for JWE key management, `jwe_t` for content encryption, and related family metadata.

## 3. Important behavior and lifetime

The module uses enum-like JOSE identifiers to select protocol processing rather than distributing algorithm-name string handling across every call site. JWK parsing/writing converts key representations to and from `crypto_key`; the common key and operation layers remain responsible for the underlying key material and cryptographic operation.

The existing status matrix in [JOSE overview](jose-overview.md) is preserved from the source documentation. Its `O`/`-` marks and TODO list are not newly verified in this pass. In particular, the old TODO mentions disabling `RSA1_5`, JWK SHA-256 thumbprints, post-quantum drafts, and Edwards-curve encryption; the RFC 7638 test source and current AKP vectors exist, so that old list may be stale and should be reviewed rather than interpreted as a reliable current backlog.

## 4. Example from the source tests

The test sources include JWK loading and PEM interoperability (`testcase_rfc7515.cpp`), RFC 7517 JWK examples (`testcase_rfc7517.cpp`), thumbprint examples (`testcase_rfc7638.cpp`), and RFC 8037 X25519/Ed25519-family cases (`testcase_rfc8037.cpp`). The AKP test uses `crypto_keychain::add_ossl3` for ML-DSA-44/65/87 and signs/verifies through `json_web_signature`; it is gated on OpenSSL 3.5 or newer.

## 5. Relationships

```text
JWK JSON ─► json_web_key ─► crypto_key / crypto_keychain
                                  │
JOSE alg name ─► JOSE identifiers + crypto_advisor metadata
                                  │
                                  ▼
                         JWS / JWE processing
                                  │
                                  ▼
                            crypto/basic
```

- `../advisor/` supplies shared algorithm/resource metadata.
- `../basic/` supplies keys and cryptographic operations.
- `../cose/` has a related key/algorithm boundary for CBOR Object Signing and Encryption, but uses COSE's own identifiers and serialization.

## 6. References

- `types.hpp`
- `json_web_key.hpp/.cpp`
- `../advisor/crypto_advisor_jose.cpp`
- `test/testcase/jose/testcase_rfc7517.cpp`
- `test/testcase/jose/testcase_rfc7638.cpp`
- `test/testcase/jose/testcase_rfc8037.cpp`
- `test/testcase/jose/testcase_akp.cpp`
