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

# Crypto

## 1. Role

`sdk/crypto/` is hotplace's cryptographic subsystem. It contains reusable cryptographic primitives and key abstractions, algorithm/parameter metadata, protocol-oriented security formats, and backend/provider integration.

Its central responsibility is to provide cryptographic operations and key handling that can be reused by higher-level consumers. It does not own every protocol's sequencing or trust semantics: TLS/DTLS/QUIC handshake and transport state live in `sdk/net`, while JOSE, COSE, and Authenticode each define their own format-specific processing and verification rules.

## 2. Data Model

The source is organized into cooperating layers:

| Area | Responsibility | Boundary |
|---|---|---|
| [`basic/`](basic/README.md) | Cipher/AEAD, digest and transcript-hash primitives, MAC, KDF, key objects and exchange, signatures, PRNG, and common PQC operations | Performs or adapts cryptographic operations; does not define complete protocol flows |
| [`advisor/`](advisor/README.md) | Algorithm, parameter, OID, backend, TLS, JOSE and COSE metadata lookup | Describes identifiers and lookup relationships; metadata presence alone does not prove backend availability |
| [`cose/`](cose/README.md) | COSE message structures and cryptographic processing over CBOR | Owns COSE object/message semantics, not general CBOR encoding |
| [`jose/`](jose/README.md) | JWS, JWE, JWK and JWA processing over JSON-oriented representations | Owns JOSE serialization and processing, not the underlying primitive implementations |
| [`authenticode/`](authenticode/README.md) | Windows PE Authenticode verification | Format-specific signature/digest and certificate verification, not a general-purpose PKI framework |
| [`oqs/`](oqs/README.md) | Optional OpenSSL 3 provider adapter for post-quantum algorithms | Integrates with an external provider; it does not implement the algorithms itself |

Conceptually, `basic` supplies operations and key abstractions; `advisor` supplies lookup metadata; COSE and JOSE compose those facilities into format-specific security objects; Authenticode verifies a PE-specific signed format; and OQS is an optional provider integration path rather than a peer message format.

### Compact source map

```text
crypto
├── basic
│   ├── crypt: symmetric cipher / AEAD / public-key encryption
│   ├── digest: hash / transcript hash
│   ├── mac: HMAC / CMAC / OTP
│   ├── sign: DSA / ECDSA / EdDSA / ML-DSA / RSA
│   ├── key: key objects / generation / key exchange
│   ├── kdf: HKDF / PBKDF2 / scrypt / Argon2
│   └── PRNG / common PQC operations
├── advisor: identifiers / algorithm parameters / backend mappings
├── JOSE: JSON security-message formats
├── COSE: CBOR security-message formats
├── OQS: optional OpenSSL provider adapter
└── Authenticode: Windows PE signature verification
```

This is a topic map, not a class-inheritance diagram or a guarantee that every algorithm is enabled in every build. In particular, the OQS path depends on build-time inclusion and runtime provider availability.

### Start from the problem you need to solve

The module pages retain the implementation and standards detail. If you are new to a particular cryptographic task, start with the matching caller-level example below, then follow the data model and behavior flow in that page.

| Problem to solve | Start here | What the example helps you see |
|---|---|---|
| Encrypt bytes and recover them | [Symmetric encryption and AEAD](basic/crypt/README.md#practical-use-build-a-cipher-round-trip-bytes-then-release-it) | How the algorithm, key, nonce/IV and output relate; for AEAD, why AAD and the authentication tag are part of the contract. |
| Calculate a digest or keep a running protocol transcript hash | [Digest and transcript hash](basic/digest/README.md) | Distinguish a one-shot hash from accumulated ordered messages and checkpoint snapshots. |
| Check whether a message was changed and came from a key holder | [MAC and OTP](basic/mac/README.md) or [digital signatures](basic/sign/README.md) | MACs require shared secret material; signatures separate signing with private material from verification with public material. |
| Derive key bytes from existing secret material | [KDF](basic/kdf/README.md) | How digest, input keying material, salt, context/info and output length determine a derivation. Password hardening is a different task from HKDF. |
| Establish matching key-agreement output between peers | [Key material and exchange](basic/key/README.md#practical-use-exchange-public-shares-and-compare-derived-secrets) | Each peer retains local private material, exchanges public share bytes, and derives a secret; this alone is not peer authentication or a complete handshake. |
| Sign or encrypt a structured JSON message | [JOSE](jose/README.md) | How JWS/JWE processing combines keys, algorithm identifiers, serialization and the underlying primitives. |
| Sign or encrypt a CBOR message | [COSE](cose/README.md) | How a protected header selects the operation and how the encoded message is processed. |
| Check a Windows PE file's Authenticode signature | [Authenticode verifier](authenticode/authenticode_verifier.md) | How PE digest comparison and certificate/trust checks fit together, including revocation inputs. |
| Experiment with post-quantum operations | [OQS provider adapter](oqs/README.md) | How provider discovery and capability gates precede KEM/signature operations; external provider and OpenSSL version matter. |

These examples demonstrate API use and specific source paths, not universal algorithm availability or production security policy. The caller still has to check operation results and follow the relevant protocol's key, nonce, trust, and validation requirements.

### Detailed source-tree documents

- [basic/key/README.md](basic/key/README.md) — key representation, construction, generation, key selection, and classical/hybrid key exchange.
- [basic/crypt/README.md](basic/crypt/README.md) — symmetric encryption, AEAD, public-key encryption, and backend boundaries; the cipher inventory is in [basic/README.md](basic/README.md#7-developer-notes).
- [basic/digest/README.md](basic/digest/README.md) and [basic/mac/README.md](basic/mac/README.md) — digest/transcript hashing, MACs, and CBC-HMAC context; cross-directory digest/HMAC inventories are in [basic/README.md](basic/README.md#7-developer-notes).
- [basic/kdf/README.md](basic/kdf/README.md) and [basic/sign/README.md](basic/sign/README.md) — key derivation and signatures. Curve taxonomy and OID examples are preserved in [basic/README.md](basic/README.md#7-developer-notes) under Developer Notes.
- [advisor/README.md](advisor/README.md) — lookup domains, resource tables, aliases, and backend mapping.
- [cose/README.md](cose/README.md) — consolidated COSE data model, encryption/signature/MAC flows, algorithm inventory, and CWT boundary; [cose/cose-overview.md](cose/cose-overview.md) retains the developer-maintained identifier table.
- [jose/jose-overview.md](jose/jose-overview.md), [jose/jose-object-model.md](jose/jose-object-model.md), [jose/jose-key-and-algorithms.md](jose/jose-key-and-algorithms.md), and [jose/jose-signing-encryption.md](jose/jose-signing-encryption.md) — JOSE objects, key/algorithm selection, and signing/encryption flows.
- [authenticode/authenticode_verifier.md](authenticode/authenticode_verifier.md) and [authenticode/authenticode-pe-plugin.md](authenticode/authenticode-pe-plugin.md) — verifier orchestration and PE-specific digest handling.
- [oqs/oqs-overview.md](oqs/oqs-overview.md), [oqs/oqs-provider-adapter.md](oqs/oqs-provider-adapter.md), and [oqs/oqs-tests.md](oqs/oqs-tests.md) — optional provider integration and its source-test boundaries.

## 3. Behavior Model

### Build and provider boundary

[`CMakeLists.txt`](CMakeLists.txt) declares dependencies on the base and IO SDK modules and links OpenSSL libraries; the exact library names depend on platform/compiler configuration. The OQS adapter source files are added only when `SUPPORT_OQS` is enabled. Its usability therefore depends on build configuration, OpenSSL 3 provider support, and the separately installed provider/runtime—not merely on the adapter files being present.

A module's presence under `sdk/crypto/` does not imply that every algorithm, provider, format feature, or trust-policy decision is available in every build. Consult the module-specific implementation and source tests before making a capability claim.

The Authenticode PE verifier calculates the PE-specific Authenticode image digest, compares it with the digest described by the signed content, and verifies signer/certificate material. The current sample sets `authenticode_ctrl_t::set_crl` to `1` (CRL download enabled); its source comment notes that this can be set to `0` for air-gapped networks. The presence of revocation-check code does not by itself prove a complete production revocation policy.

## 4. Relationships
- [`sdk/base/`](../base/README.md) — foundational types, encoding, strings, and utility support.
- [`sdk/io/`](../io/README.md) — CBOR, JSON, ASN.1/DER, OID conversion, and other representations consumed by crypto-related paths.
- [`sdk/net/`](../net/README.md) — protocol consumers such as TLS/DTLS/QUIC and HTTP authentication.
- [`test/testcase/crypto/`](../../test/testcase/crypto/README.md) — primitive and backend-oriented testcase entry point.
- [`test/testcase/cose/`](../../test/testcase/cose/) and [`test/testcase/jose/`](../../test/testcase/jose/) — format-specific testcase sources and vectors.
- [`test/applet/authenticode/`](../../test/applet/authenticode/) — external-file Authenticode example.

## 5. References

The following standards and background resources help interpret the source. Their inclusion does not imply that every feature is implemented, enabled, or fully conformant.

### Books
- *Secure Programming Cookbook for C and C++* — O'Reilly.

### RFCs

**Primitives, key derivation, and password-based functions**
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) — HMAC: Keyed-Hashing for Message Authentication.
- [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394) — AES Key Wrap Algorithm.
- [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) — HOTP: An HMAC-Based One-Time Password Algorithm.
- [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493) — The AES-CMAC Algorithm.
- [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649) — AES Key Wrap with Padding.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- [RFC 6070](https://www.rfc-editor.org/rfc/rfc6070) — PKCS #5: PBKDF2 test vectors.
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) — TOTP: Time-Based One-Time Password Algorithm.
- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914) — The scrypt Password-Based Key Derivation Function.
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) — PKCS #1: RSA Cryptography Specifications Version 2.2.
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) — ChaCha20 and Poly1305 for IETF Protocols.
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.

**JOSE, COSE, and data representations**
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) — JSON Web Signature (JWS).
- [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) — JSON Web Encryption (JWE).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) — JSON Web Key (JWK).
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) — JSON Web Algorithms (JWA).
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JSON Web Token (JWT).
- [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520) — Examples of Protecting Content Using JOSE.
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) — ECDH and signatures in JOSE.
- [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152) — COSE, earlier version.
- [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392) — CBOR Web Token (CWT).
- [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — Concise Binary Object Representation (CBOR).
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) — COSE: Structures and Process.
- [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) — COSE: Initial Algorithms.
- [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338) — COSE Countersignatures.

**Protocol and authenticated-encryption context**
- [RFC 7366](https://www.rfc-editor.org/rfc/rfc7366) — Encrypt-then-MAC for TLS and DTLS.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — The Transport Layer Security (TLS) Protocol Version 1.3.

**openssl**
- [docs](https://docs.openssl.org/3.5/)

**draft**
- [RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation](https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05)
- [Authenticated Encryption with AES-CBC and HMAC-SHA](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt)
- [draft-ietf-tls-mlkem-05](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/)
- [draft-ietf-tls-ecdhe-mlkem-03](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [Use of ML-DSA in TLS 1.3](https://www.iana.org/go/draft-ietf-tls-mldsa-00)

### Online resources
- [OpenSSL libcrypto introduction](https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/)
- [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml)
- [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml)
- [IANA TLS parameters registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)
- [COSE examples](https://github.com/cose-wg/Examples)
- [OID repository](https://oid-base.com/)
- [Standard curve database](https://neuromancer.sk/std/)
- [Authenticated Encryption with AES-CBC and HMAC-SHA](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt)
- [JSON parser performance comparison — nativejson-benchmark](https://github.com/miloyip/nativejson-benchmark)
- [JSON parser performance comparison — Java](https://github.com/fabienrenaud/java-json-benchmark)
- [Mac-then-Encrypt https://tls12.xargs.org](https://tls12.xargs.org)