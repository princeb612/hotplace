## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Digital Signatures and Verification

## 1. Role

This directory provides a common `sign` / `verify` interface over several signature families. The value of the abstraction is not that all algorithms behave identically, but that protocol-facing code can select a scheme while algorithm-specific implementation details remain behind the interface. HMAC is also exposed through this shared facade for consumers such as JOSE that use common signing/authentication workflows.

## 2. Data Model

| Type | Responsibility |
|---|---|
| `openssl_sign` | Backend that dispatches by key type and signature category and invokes OpenSSL signing/verification operations. |
| `crypto_sign` | Common operation object exposing `sign()` and `verify()` for byte streams or `binary_t`, with signature category, digest and RSA-PSS salt-length configuration. |
| `crypto_sign_builder` | Holds the requested signature category/scheme, digest and any scheme-specific options, then builds the appropriate `crypto_sign` implementation. The selected key and backend availability remain separate inputs/constraints. |
| `crypto_sign_digest` / `crypto_sign_digestsign` | Separate the conventional digest-then-sign path from the backend's combined DigestSign-style path. |
| Algorithm-specific classes | Implement RSA PKCS#1 v1.5, RSA-PSS, DSA, ECDSA, EdDSA, HMAC, ML-DSA and SLH-DSA behavior. |

### Why the implementations are separate

- **RSA PKCS#1 v1.5** and **RSA-PSS** are both RSA signatures, but use different encodings and verification parameters; PSS includes salt-length policy.
- **DSA** and **ECDSA** are discrete-log signature families with their own key/parameter handling and signature encodings.
- **EdDSA** uses a different signing API contract from the conventional “hash message, then sign digest” path; the source has a dedicated DigestSign-style branch.
- **HMAC** is a keyed message-authentication operation rather than a public-key digital signature, but the common facade exposes it for shared sign/verify workflows.
- **ML-DSA** and **SLH-DSA** are post-quantum signature families with their own backend classes and provider/version constraints.

## 3. Behavior Model

### 3.1 Resolve the requested scheme, then dispatch

```text
caller / protocol identifier
    ├─ signature category + digest
    ├─ TLS signature-scheme ID
    └─ JOSE JWS algorithm
              |
              v
       crypto_sign_builder
              |
              v
          crypto_sign
              |
              v
        openssl_sign
              |
              v
 resolve signature hint/category + digest
              |
              v
 combine scheme with actual key type
              |
              v
 key-type-specific EVP sign / verify operation
              |
              v
 signature bytes or verification status
```

The builder resolves the requested identifier into a primitive configuration; the backend still needs compatible key material and an available implementation. A scheme name in a protocol registry is not proof that the current OpenSSL/provider build can execute it.

Signing and verification must use compatible algorithm parameters and intended public/private key material. Digest-sign and message-sign paths differ in where hashing is performed, so callers must not accidentally hash input twice or assume all algorithms accept pre-hashed input.

For TLS, the selected signature scheme constrains key type and digest/version semantics. For JOSE, the `jws_t` identifier is part of the JWS algorithm contract; this module does not serialize the JWS signing input or produce compact/JSON JOSE messages.

### 3.2 Concrete caller path from `testcase_crypto_sign.cpp`

The common-interface testcase loads named key material into a `crypto_key`, then resolves a key by both key identifier and key type. Each case builds a signing object from a signature category and digest, signs the same sample message, and verifies the produced signature:

```text
test key collection (Ed25519 / Ed448 / P-521 / P-384 / P-256 / ...)
  -> find(kid, kty)
  -> crypto_sign_builder
       set_category(category)
       set_digest(digest)
       build()
  -> sign(pkey, message, signature)
  -> verify(pkey, message, signature)
  -> check operation result
  -> for EC keys, check the expected signature size
  -> release signing object
```

This testcase is useful because it varies the **key family/curve and digest combination**, rather than merely repeating one successful round trip. EdDSA cases use an empty digest selection; ECDSA cases pair named curves with SHA-2 digests. The P-521/SHA-256 and P-521/SHA-384 cases, and the P-384/SHA-256 case, are marked as expected failures, while compatible combinations are expected to sign and verify successfully.

The `expect` flag controls the assertion path: expected-success cases check the sign and verify return codes; expected-failure cases require signing to fail and record verification through the negative-test helper. The testcase also checks the ECDSA signature length using the advisor's expected-size result. If the requested key cannot be found, it records `not_supported` rather than silently treating the case as a successful signature test.

This is a primitive-level test of the common signing interface. It does not construct JWS/COSE messages, and a same-key sign/verify round trip does not by itself establish interoperability with an independent implementation or a protocol's complete algorithm policy.

### 3.3 Comparative map

The directory names mix three different dimensions: operation/API path, cryptographic family, and signature encoding. They should not be read as ten unrelated signature algorithms.

| Implementation | Key model | Input and signing path | Verification distinction |
|---|---|---|---|
| `digest` (`crypto_sign_digest`) | Selected through the supplied `EVP_PKEY`; the backend dispatches by key type/category | In the source, `sign_digest` uses `EVP_DigestSignInit/Update/Final` with the selected digest. Despite the class name, this is not simply a standalone hash operation that returns a digest. | `verify_digest` uses the matching `EVP_DigestVerify*` path. The key type and signature category still determine what operation OpenSSL performs. |
| `digestsign` (`crypto_sign_digestsign`) | Depends on the selected key family | Uses the combined DigestSign-style backend path without choosing an external digest in this wrapper. It is used by key families such as EdDSA and, on supported builds, ML-DSA/SLH-DSA. | Uses the matching DigestVerify-style path; algorithm-specific parameter rules still apply. |
| `dsa` | DSA public/private key pair | Message is processed with the selected digest before DSA signing. | Public-key verification checks the DSA signature under the corresponding key parameters. DSA is legacy for new designs; current FIPS policy does not approve DSA signature generation, though verification may remain permitted. |
| `ecdsa` | EC public/private key pair | Message is processed with the selected digest; signature arithmetic uses the EC group and private key. | Public-key verification checks the ECDSA result. Curve/key compatibility and the signature encoding matter. |
| `eddsa` | Ed25519/Ed448 key (OKP family in hotplace) | Uses the `digestsign` path; EdDSA owns its message-processing rules rather than taking an arbitrary external digest selection here. | Uses the matching EdDSA verification operation. Do not treat it as interchangeable with ECDSA merely because both involve elliptic curves. |
| `hmac` | Shared secret key (octet key) | Computes a keyed message authentication code using the selected hash. | The verifier needs the same secret and recomputes the MAC. This is symmetric message authentication, not a public-key digital signature or non-repudiation mechanism. |
| `rsa_pkcs15` | RSA key pair | Hashes the message and applies RSASSA-PKCS1-v1_5 encoding before the RSA private-key operation. | Public-key verification checks the PKCS#1 v1.5 encoded digest and signature. It is not the same scheme as RSA-PSS. |
| `rsa_pss` | RSA or RSA-PSS key | Uses RSASSA-PSS encoding, including digest and salt-length configuration. | Verification must use compatible PSS parameters, including the expected salt-length policy. A matching RSA key alone does not make the two RSA signature schemes interchangeable. |
| `mldsa` | ML-DSA key (post-quantum public-key signature) | Uses the combined signing path and the algorithm's own parameter set; the hotplace builder enables this category only when compiled against OpenSSL 3.5 or later. | Checks an ML-DSA signature using the matching ML-DSA key and parameter set. |
| `slhdsa` | SLH-DSA key (post-quantum, hash-based public-key signature) | Uses the combined signing path and the selected SLH-DSA variant. It is also guarded in the builder by the OpenSSL 3.5 version check. | Checks an SLH-DSA signature using the matching variant and key. Its hash-based construction differs from ML-DSA; the two are not interchangeable. |

### 3.4 Verification dispatch: signature algorithm first, key type second

The primary decision is the requested signature algorithm, not the key type alone. In the source, `sig` is resolved through `hintof_signature(sig)`; the resulting hint supplies both the signature category and digest. Only then does the backend combine that category with the actual key type to choose an operation or reject the request.

```text
signature algorithm: sig
          |
          v
advisor->hintof_signature(sig)
          |
          +-- no hint ----------------------> bad_request
          |
          v
    +---------------------+
    | categoryof(hint)    |
    | typeof_alg(hint)    |
    +---------------------+
          |
          v
    category + hash_alg
          |
          v
  key type and scheme compatibility
          |
          +-- RSA / RSA-PSS
          |      |
          |      +-- rsassa_pkcs15 --> PKCS#1 v1.5
          |      |
          |      +-- rsassa_pss ----> PSS
          |      |                    (digest + salt length)
          |      |
          |      +-- unsupported combination
          |                           --> bad_request
          |
          +-- EC  -----------------> ECDSA
          +-- DSA -----------------> DSA
          +-- OKP -----------------> EdDSA DigestSign/Verify path
          |
          +-- Octet
          |      +-- dgst ---------> digest-signature path
          |      +-- hmac ---------> HMAC with shared secret
          |      +-- unsupported --> bad_request
          |
          +-- ML-DSA -------------> ML-DSA helper/path*
          +-- SLH-DSA ------------> SLH-DSA helper/path*
          +-- unsupported key/category pair --> bad_request

* ML-DSA and SLH-DSA dispatch is compile-guarded for OpenSSL 3.5+.
  They share a helper path in this backend, but are different algorithms.
```

This is a two-dimensional dispatch: **the signature identifier selects the intended scheme and its parameters; the key type determines whether and how that scheme can be executed.** For example, choosing `rsassa_pkcs15` versus `rsassa_pss` selects different RSA signature operations even when the key belongs to the RSA family. Conversely, an RSA-family key does not by itself establish that every RSA scheme is valid for that key: RSA-PSS-restricted key parameters and OpenSSL's key/operation checks still matter. The diagram summarizes the dispatch structure; it does not claim that every pair accepted by a switch statement is cryptographically or protocol-valid.

The same separation matters in TLS. A TLS signature-scheme identifier (such as an RSA-PSS or ECDSA scheme) determines the signature operation and associated digest rules, while the peer's key and negotiated protocol constraints determine whether that scheme is usable. In TLS 1.3, this is distinct from the cipher suite: the cipher suite selects the record-protection algorithms and hash, whereas CertificateVerify uses a signature scheme. Avoid using “cipher suite” as a synonym for the signature algorithm.

### 3.5 What is actually different during verification?

The common `verify()` interface hides the dispatch, not the mathematics. In `openssl_sign.cpp`, hotplace selects the operation from the key type and signature category:

- RSA/RSA-PSS keys route to either PKCS#1 v1.5 or PSS verification; these use the same broad RSA key family but different encoded-message rules.
- EC keys route to ECDSA verification; DSA keys route to DSA verification.
- OKP keys route to the DigestSign/DigestVerify-style operation used by EdDSA.
- Octet keys distinguish the `dgst` and `hmac` categories. HMAC verification is keyed recomputation, not public-key verification.
- ML-DSA and SLH-DSA are included in the OpenSSL 3.5+ dispatch. The current backend routes both through the shared `verify_mldsa` helper, which delegates to the common DigestVerify-style path; this shared helper does not mean the algorithms have the same signature construction.

The caller must provide the original message bytes expected by the selected path, not a pre-hashed digest unless that specific API contract explicitly calls for one. The wrapper's digest setting, the algorithm's own message-processing rules, and protocol-level signing input are separate concepts.

### 3.6 OpenSSL 3 support: version and provider matter

The following is an upstream capability guide, not a guarantee that every hotplace build can execute every operation. The concrete hotplace code has its own compile-time gates, and runtime availability also depends on the OpenSSL build, provider configuration, key encoding, and parameters.

| Family/category | Upstream OpenSSL 3 guidance | hotplace source boundary |
|---|---|---|
| RSA PKCS#1 v1.5 / RSA-PSS | Supported in OpenSSL 3.x providers; exact policy and parameter constraints depend on the provider. | Separate categories and backend functions; PSS additionally carries salt-length configuration. |
| DSA / ECDSA | Available in OpenSSL 3.x. DSA has legacy/security-policy limitations; FIPS approval is not equivalent to implementation availability. | Separate DSA and ECDSA backend paths. |
| EdDSA | Ed25519 and Ed448 are available in OpenSSL 3.x. These use algorithm-specific message-processing rules rather than a caller-selected digest in the hotplace wrapper. | `eddsa` builds the `crypto_sign_digestsign` wrapper. |
| HMAC | Available in OpenSSL 3.x; requires compatible shared-secret key material and digest selection. | Octet key + HMAC category dispatch. |
| ML-DSA / SLH-DSA | Added to upstream OpenSSL in 3.5. OpenSSL 3.0–3.4 should not be described as supporting these algorithms through the built-in provider implementations. | The builder and key-type dispatch use `OPENSSL_VERSION_NUMBER >= 0x30500000L` guards. Runtime provider support must still be checked. |

For operational compatibility notes, record the exact OpenSSL minor version and provider (for example, default or FIPS), rather than a single “OpenSSL 3: yes/no” flag. Provider presence, FIPS approval, compile-time availability, and successful execution are four different claims.

### 3.4 Concrete protocol consumer: TLS CertificateVerify

TLS CertificateVerify uses the negotiated TLS signature scheme to build the primitive signer. The TLS layer constructs the protocol-defined CertificateVerify input; `crypto_sign` performs only the selected signature operation:

```cpp
// Reduced from sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.cpp
crypto_sign_builder builder;
auto sign = builder.set_tls_sign_scheme(scheme).build();
if (sign) {
    basic_stream tosign;
    construct_certificate_verify_message(session, dir, tosign);
    ret = sign->sign(pkey, tosign.data(), tosign.size(),
                     signature, sign_flag_format_der);
    sign->release();
} else {
    ret = errorcode_t::not_supported;
}
```

This caller makes the protocol/primitive boundary concrete: TLS selects the scheme and constructs the signed message; the common signature layer dispatches by scheme and key type. The corresponding verification path reconstructs the same CertificateVerify input before verifying. A successful primitive signature operation alone does not validate the certificate chain or complete the TLS handshake.

## 4. Relationships
- `../../advisor/README.md` maps signature names, key types, TLS signature schemes, JOSE identifiers and backend metadata.
- `../key/README.md` supplies key objects and key-generation/serialization facilities.
- `../digest/README.md` provides digest operations for digest-sign paths.
- `../mac/README.md` documents MAC primitives; HMAC is also exposed through this signing abstraction.
- `sdk/net/tls/` chooses TLS signature schemes and constructs the signed handshake input.
- `sdk/crypto/jose/` constructs JWS signing input and serialization around these primitive operations.
- `sdk/crypto/cose/` constructs COSE Sig_structure and delegates the signature operation here.

### Implementation entry points

- `crypto_sign.cpp`, `crypto_sign_builder.cpp`
- `crypto_sign_digest.cpp`, `crypto_sign_digestsign.cpp`
- `openssl_sign.cpp` and algorithm-specific `crypto_sign_*.cpp` / `openssl_sign_*.cpp`
- `test/testcase/crypto/sign/`

### Source-test evidence

- `testcase_crypto_sign.cpp` exercises the common interface.
- `testcase_rsassa.cpp` and RSA vectors cover RSA signatures; `testcase_ecdsa.cpp` and ECDSA vectors cover ECDSA.
- `testcase_hmac.cpp` covers HMAC through the signing facade.
- `testcase_mldsa.cpp` and `testcase_slhdsa.cpp` cover post-quantum signature paths. Availability depends on the build/provider used for those tests.
- The source paths establish coverage targets, not execution in the current environment.

## 5. References
- RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2.
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).
- FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA).
- [OpenSSL 3.5 default provider](https://docs.openssl.org/3.5/man7/OSSL_PROVIDER-default/) — upstream algorithm availability, including ML-DSA and SLH-DSA.
- [OpenSSL 3.6 DSA signature implementation](https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-DSA/) — DSA signature behavior and FIPS policy notes.
- [OpenSSL EVP signing and verifying](https://docs.openssl.org/3.5/man7/) — reference index for provider signature implementations.
