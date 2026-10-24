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

### Start from the problem you need to solve

The module pages retain the implementation and standards detail. If you are new to a particular cryptographic task, start with the matching caller-level example below, then follow the data model and behavior flow in that page.

| Problem to solve | Start here | What the example helps you see |
|---|---|---|
| Encrypt bytes and recover them | [Symmetric encryption and AEAD](basic/crypt/README.md#practical-use-build-a-cipher-round-trip-bytes-then-release-it) | How the algorithm, key, nonce/IV and output relate; for AEAD, why AAD and the authentication tag are part of the contract. |
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
- [`crypto-mindmap.md`](crypto-mindmap.md) — compact topic map.
- [`crypto-references.md`](crypto-references.md) — curated external standards, book, and online-reference list.

## 5. References
- [OpenSSL libcrypto introduction](https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/)
- [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml)
- [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml)
