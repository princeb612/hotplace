## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Crypto

## 1. Role

`sdk/crypto/` is hotplace's cryptographic subsystem. It contains reusable cryptographic primitives and key abstractions, identifier/parameter metadata, protocol-oriented formats, and backend/provider integration. The directory-level map is an entry point; implementation details belong in the corresponding subdirectory documents.

## 2. Model

The source is organized into cooperating layers:

- [`basic/`](basic/README.md) — primitive operations and key objects, largely backed by OpenSSL.
- [`advisor/`](advisor/README.md) — metadata and lookup functions that map algorithm, parameter, OID, and protocol identifiers to supported capabilities or backend identifiers.
- [`cose/`](cose/README.md) — CBOR Object Signing and Encryption structures and processing.
- [`jose/`](jose/README.md) — JSON Object Signing and Encryption structures and processing.
- [`authenticode/`](authenticode/README.md) — Windows PE Authenticode verification, a format-specific verifier rather than a general-purpose certificate framework.
- [`oqs/`](oqs/README.md) — optional OpenSSL 3 provider integration for post-quantum algorithms; the adapter is not itself an implementation of those algorithms.

Conceptually, `basic` supplies operations and key abstractions; `advisor` supplies lookup metadata; format-specific modules compose those facilities for their own data formats. OQS is an optional backend/provider integration path rather than a peer message format.

## 3. Important behavior and lifetime

- The build definition in [`CMakeLists.txt`](CMakeLists.txt) declares dependencies on the base and IO SDK modules and links OpenSSL libraries; the exact library names depend on platform/compiler configuration.
- OQS source files are added only when `SUPPORT_OQS` is enabled. Availability therefore depends on build configuration and the separately installed provider/runtime, not merely on the presence of the adapter source.
- A module's presence under `sdk/crypto/` does not imply that every algorithm, provider, format feature, or trust-policy decision is available in every build. Consult the module-specific source and tests before making a capability claim.
- Authenticode verification and JOSE/COSE message processing have different format and trust semantics; they should not be treated as interchangeable certificate-verification APIs.

## 4. Example from the source tests

Use the testcase directories as the source-backed index for behavior rather than treating this overview as proof that a test was executed:

- [`test/testcase/crypto/`](../../test/testcase/crypto/README.md) — primitive operations, key/signature processing, test vectors, and provider/PQC-related cases.
- [`test/testcase/cose/`](../../test/testcase/cose/) — COSE-focused tests.
- [`test/testcase/jose/`](../../test/testcase/jose/) — JOSE-focused tests.
- [`test/applet/authenticode/`](../../test/applet/authenticode/) — Authenticode applet/example.

This document records source-tree relationships only; it does not claim that these tests were run as part of the documentation update.

## 5. Relationships

- [`sdk/base/`](../base/README.md) — foundational types, encoding, strings, and utility support.
- [`sdk/io/`](../io/README.md) — CBOR, JSON, ASN.1/DER, and other representations consumed by crypto-related paths.
- [`sdk/net/`](../net/README.md) — protocol consumers such as TLS and related network functionality.
- [`test/testcase/crypto/`](../../test/testcase/crypto/README.md) — primitive and backend-oriented test entry point.
- [`crypto-mindmap.md`](crypto-mindmap.md) — compact topic map.
- [`crypto-references.md`](crypto-references.md) — retained RFC, book, and online-reference list.

## 6. References

- [Cryptographic references](crypto-references.md)
- [OpenSSL libcrypto introduction](https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/)
- [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml)
- [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml)
