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

# JWK and JOSE algorithm mapping

## 1. Role

This record describes the boundary between JSON Web Key (JWK) material, JOSE algorithm identifiers, and hotplace's common crypto/key abstractions.

## 2. Data Model
`json_web_key` bridges JWK JSON and `crypto_key`. The source's existing status table lists these key types:

- `oct` — symmetric keys
- `RSA`
- `EC` — P-256, P-384 and P-521
- `OKP` — Ed25519, Ed448, X25519 and X448

`types.hpp` groups algorithm identifiers by protocol role: `jws_t` for JWS signature/MAC algorithms, `jwa_t` for JWE key management, `jwe_t` for content encryption, and related family metadata.

## 3. Behavior Model
The module uses enum-like JOSE identifiers to select protocol processing rather than distributing algorithm-name string handling across every call site. JWK parsing/writing converts key representations to and from `crypto_key`; the common key and operation layers remain responsible for the underlying key material and cryptographic operation.

The current source-based algorithm inventory, including the distinction between JOSE enums and shared metadata-only signature entries, is summarized in the [JOSE README](README.md). The [historical status note](jose-overview.md) retains older `O`/`-` marks and TODOs for maintainer context; they are not the authoritative current support matrix. In particular, `RSA1_5` remains present in the current JWA resource table despite the historical TODO to disable it, and RFC 7638/AKP test sources exist despite older TODO items. Neither a mapping nor a test file alone proves availability in every build.

### Real-code example: load a JWK, then select a JWS algorithm

`test/testcase/jose/testcase_rfc7515.cpp` demonstrates the key/algorithm boundary using the RFC 7515 HMAC-SHA-256 vector:

```cpp
crypto_key key;
json_web_key jwk;
jwk.load_file(&key, key_ownspec, "rfc7515.jwk");

json_web_signature jws;
std::string signature;
ret = jws.sign(&key, (char*)hs256_header, claim, signature);
ret = jws.verify(&key, signature, result);
```

The JWK loader creates the common `crypto_key` representation; the caller separately chooses the JWS operation and supplies the header/claim. The key type alone does not select the signing algorithm, and the presence of an enum/resource mapping does not prove that every backend/build supports that algorithm.
## 4. Relationships
### Source-test evidence

The test sources include JWK loading and PEM interoperability (`testcase_rfc7515.cpp`), RFC 7517 JWK examples (`testcase_rfc7517.cpp`), thumbprint examples (`testcase_rfc7638.cpp`), and RFC 8037 X25519/Ed25519-family cases (`testcase_rfc8037.cpp`). The AKP test uses `crypto_keychain::add_ossl3` for ML-DSA-44/65/87 and signs/verifies through `json_web_signature`; it is gated on OpenSSL 3.5 or newer.

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

- `types.hpp`
- `json_web_key.hpp/.cpp`
- `../advisor/crypto_advisor_jose.cpp`
- `test/testcase/jose/testcase_rfc7517.cpp`
- `test/testcase/jose/testcase_rfc7638.cpp`
- `test/testcase/jose/testcase_rfc8037.cpp`
- `test/testcase/jose/testcase_akp.cpp`
