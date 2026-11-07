# Crypto Advisor, TLS Advisor, and Backend Identity

## Review thesis

**The advisor architecture separates cryptographic identity from protocol identity and backend representation, so that TLS/QUIC vocabulary, cryptographic meaning, and OpenSSL mappings remain related without becoming one dictionary or one implementation layer.**

## Review scope

This review describes the relationship between `sdk/crypto/advisor`, `sdk/net/tls/advisor`, and the OpenSSL-facing crypto layer as they exist in revision 1124.

The important distinction is that these are **two related vocabulary/metadata layers**, not a single generic dictionary:

- `crypto_advisor` describes cryptographic identities, algorithms, parameters, aliases, and backend mappings.
- `tls_advisor` describes protocol identifiers used by TLS, DTLS, and QUIC.
- OpenSSL is a backend representation used by the crypto implementation and by the advisor mapping layer; it is not the conceptual owner of either vocabulary.

## Historical review context

The initial architecture review established the relationship model at revision 1097. That earlier pass is retained here as review history; the current document-wide assessment is based on revision 1124.

## 1. Two advisor domains

A useful high-level model is:

```text
                         protocol / crypto identifiers
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
                    ▼                                   ▼
             crypto_advisor                         tls_advisor
                    │                                   │
        ┌───────────┼───────────┐          ┌────────────┼────────────┐
        │           │           │          │            │            │
      digest       key        curve     cipher suite   group      extension
        │           │           │          │            │            │
        └───────────┴───────────┴──────────┴────────────┴────────────┘
                                      │
                                      ▼
                              crypto implementation
                                      │
                                      ▼
                                OpenSSL / EVP
```

The diagram is intentionally symmetric. `tls_advisor` is not merely a second lookup stage underneath `crypto_advisor`; each advisor owns a different identifier namespace.

## 2. `crypto_advisor`: cryptographic identity

The source directory contains a family of domain-specific lookup components:

```text
sdk/crypto/advisor/
├── crypto_advisor_crypt
├── crypto_advisor_curve
├── crypto_advisor_digest
├── crypto_advisor_encoding
├── crypto_advisor_integration
├── crypto_advisor_jose
├── crypto_advisor_key
├── crypto_advisor_sign
└── crypto_advisor_tls
```

The corresponding `resource_*.cpp` files provide static algorithm and parameter knowledge.

Conceptually:

```text
crypto identity
      │
      ├── algorithm / mode
      ├── digest
      ├── curve
      ├── key type
      ├── signature / signature scheme
      ├── encoding
      ├── JOSE / COSE identifier
      └── TLS-related crypto metadata
```

The important architectural property is separation from the primitive implementation:

```text
sdk/crypto/advisor
        │
        │ identity / metadata / mapping
        ▼
   sdk/crypto/basic
        │
        │ actual cryptographic operation
        ▼
 cipher / digest / key / signature
```

This allows protocol code to ask *what an identifier means* without embedding the entire mapping table in each protocol implementation.

## 3. OpenSSL is a backend mapping boundary

`crypto_advisor` also contains OpenSSL-specific knowledge. Typical mappings include:

```text
hotplace hint / algorithm identity
          │
          ├──────────────► OpenSSL NID
          │
          ├──────────────► EVP_MD
          │
          ├──────────────► EVP_CIPHER
          │
          └──────────────► EVP_PKEY / key metadata
```

Representative queries include `find_evp_cipher()`, `find_evp_md()`, `hintof_pkey()`, and `hintof_ossl_nid()`.

This does **not** make `crypto_advisor` an OpenSSL wrapper in the broad sense. Its primary responsibility remains identity and metadata. OpenSSL is one backend vocabulary that must be translated into or from hotplace's vocabulary.

That distinction is important when reading the source:

```text
identifier knowledge
        │
        ▼
 crypto_advisor
        │
        ├── hotplace identity
        ├── protocol identity
        └── backend identity
                  │
                  ▼
              OpenSSL
```

## 4. `tls_advisor`: protocol identity

The reviewed TLS side is broader than a TLS cipher-suite table; the 1097 pass found no material architectural change to this distinction.

The `tls_advisor` resource family covers identifiers and parameters for:

```text
TLS
 ├── alert
 ├── handshake
 ├── extension
 ├── cipher suite
 ├── group
 ├── KDF
 ├── PSK mode
 ├── AEAD
 └── secret / protection-space related values

QUIC
 ├── frame
 ├── transport parameter
 ├── error
 └── other QUIC/TLS integration identifiers
```

Therefore the useful abstraction is:

```text
protocol vocabulary
        │
        ▼
   tls_advisor
        │
        ├── TLS identifiers
        ├── DTLS identifiers
        └── QUIC identifiers
```

The fact that QUIC resources are included is significant: `tls_advisor` represents the identifier layer around the TLS/QUIC protocol boundary rather than TLS 1.3 alone.

## 5. The two advisors meet at crypto meaning

The relationship is better described as a **cross-reference** than as a strict pipeline.

```text
                 TLS / DTLS / QUIC
                        │
                        ▼
                  tls_advisor
                        │
                 protocol identity
                        │
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
       crypto meaning        protocol metadata
             │
             ▼
       crypto_advisor
             │
       ┌─────┴─────┐
       ▼           ▼
   hotplace     OpenSSL
   crypto       mapping
```

For example, a TLS cipher suite has a protocol-level identity, but its implementation also requires knowledge of the underlying AEAD/cipher, digest, key exchange group, or signature-related parameters. Those pieces belong to different namespaces even when one handshake message brings them together.

## 6. Why this separation matters in protocol code

A protocol implementation should not have to maintain its own copies of every identifier mapping.

A simplified lookup path is:

```text
wire value / configured name
          │
          ▼
     protocol advisor
          │
          ▼
 protocol-level metadata
          │
          ├──────────────┐
          │              │
          ▼              ▼
 crypto_advisor     protocol-specific logic
          │
          ▼
   crypto identity
          │
          ▼
 crypto/basic or backend
```

This becomes particularly useful for TLS and QUIC because the same cryptographic primitive may appear under several protocol-facing names or identifiers.

## 7. TLS and QUIC are structurally connected here

The development-history document describes TLS → DTLS → QUIC as a learning and implementation path. The advisor layer reveals a second, structural relationship:

```text
             TLS resource / identifier layer
                         │
                ┌────────┴────────┐
                ▼                 ▼
               TLS               QUIC
                │                 │
                └────────┬────────┘
                         ▼
                    tls_advisor
```

This should not be confused with the historical development sequence. One is **how the implementation evolved**; the other is **how the current identifier layer is organized**.

## 8. Relation to ASN.1 and OID-based identity

Cryptographic identity also crosses into ASN.1-oriented code through object identifiers and encoded structures.

A useful conceptual path is:

```text
ASN.1 / OID
     │
     ▼
cryptographic identity
     │
     ├── crypto_advisor
     │       │
     │       └── backend mapping
     │
     └── protocol-specific advisor
```

The important relationship here is not that the source spans several directories. It is that an object identifier or algorithm name can acquire different meanings at different architectural levels, and the advisor layer provides a place to normalize those meanings without moving protocol semantics into the crypto backend.

## 9. Resource tables are part of the architecture

The `resource_*.cpp` files should be viewed as data-backed implementation infrastructure, not as miscellaneous lookup helpers.

```text
                    advisor interface
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
      domain-specific logic      resource tables
              │                       │
              └───────────┬───────────┘
                          ▼
                  normalized metadata
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
       protocol consumers       crypto/backend
```

This also explains why advisor tests are valuable even though they do not test cryptographic mathematics. A broken table entry can connect the right algorithm name to the wrong backend representation, or make aliases disagree about the same curve.

## 10. Verification invariants

The existing advisor testcase records several useful invariants:

- advertised feature domains can be enumerated and queried;
- aliases such as `P-256`, `prime256v1`, and `secp256r1` resolve to the same curve metadata;
- cipher resource entries remain consistent across their public name, scheme, algorithm/mode, and backend fetch mapping.

These are **identity invariants**, not primitive correctness tests.

The distinction is useful when navigating the test tree:

```text
crypto/basic tests
    → does the primitive work?

advisor tests
    → does the identity/resource mapping remain coherent?

TLS tests
    → does the protocol consume the resource mapping correctly?
```

## 11. Relation to the TLS/DTLS/QUIC implementation

The advisor layer sits beside, rather than inside, the protocol state machines and wire-format classes.

```text
                  tls_advisor
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        TLS           DTLS         QUIC
          │            │            │
          └────────────┼────────────┘
                       │
                 protocol logic
                       │
                       ▼
                 crypto services
                       │
                       ▼
                 crypto_advisor
                       │
                       ▼
                 crypto/basic
                       │
                       ▼
                    OpenSSL
```

This is intentionally not a strict call graph. It is an architectural dependency picture: protocol code needs protocol identifiers, and crypto code needs cryptographic identity/backend mappings.

## 12. Architectural consequence

The advisor layer is easy to misunderstand if each file is read independently. The interesting part is not the individual lookup function; it is the fact that hotplace maintains several identifier vocabularies and translates between them.

The architectural relationship is therefore:

```text
       protocol vocabulary
              │
              ▼
         tls_advisor
              │
              │ crypto meaning
              ▼
        crypto_advisor
              │
              │ backend meaning
              ▼
         OpenSSL / EVP
```

while `crypto_advisor` independently also connects to JOSE, COSE, curve/key/digest/signature identities, and other crypto namespaces.

This makes the advisors a **translation and consistency layer** rather than a cryptographic implementation layer.


## 13. TLS resource identity and runtime support policy

The TLS cipher-suite resource table must not be read as a list of cipher suites that the implementation will negotiate.

`sdk/net/tls/advisor/resource_ciphersuite.cpp` is also used as an identifier and diagnostic catalogue. The flags distinguish catalogue presence from operational eligibility:

- `tls_flag_secure | tls_flag_support`: recommended and supported.
- `tls_flag_support` without `tls_flag_secure`: retained for legacy or debugging purposes, but still marked as supported by the implementation's resource policy.
- No `tls_flag_support`: recognized metadata may remain available for inspection, but the entry is not eligible for ordinary negotiation.

This distinction is important when interpreting legacy RSA, static DH, and static ECDH entries. Their presence in the resource table alone is not evidence that the handshake can select them. In the reviewed resource definitions, the static DH and static ECDH families are not marked with `tls_flag_support`; ECDHE remains a separate supported key-exchange family.

The relevant implementation gates reinforce this separation:

- `tls_protection_context::select_from()` filters peer-offered cipher suites by `tls_flag_support` before adding them to the supported candidate set.
- The server-side ServerHello cipher-suite setter rejects entries without `tls_flag_support` by default. The explicit `session_debug_deprecated_ciphersuite` option is intended for validating older test vectors that contain deprecated cipher suites, rather than for real-world TLS negotiation or as a way to enable those suites for ordinary use. It is a test/diagnostic compatibility switch, not an operational security-policy recommendation.
- The supported-versions extension only adds versions whose resource hint has `support` enabled.
- The version resource table marks TLS 1.0/1.1 and DTLS 1.0/1.1 unsupported, while TLS 1.2/1.3 and DTLS 1.2/1.3 are marked supported.

### RFC policy cross-check

The first-pass review of RFC 8996, RFC 9852, and RFC 10015 therefore does not identify a required change to the resource table merely because historical cipher-suite identifiers are retained.

- **RFC 8996** deprecates TLS 1.0, TLS 1.1, and DTLS 1.0. The current version-support flags already exclude these from ordinary supported-version advertisement/selection.
- **RFC 9852** updates the TLS security baseline for new protocols using TLS and requires TLS 1.3 for such new protocol designs. This does not mean that an existing general-purpose TLS implementation must remove TLS 1.2 compatibility. DTLS has a distinct deployment and transition context.
- **RFC 10015** updates the TLS 1.2/DTLS 1.2 security guidance, including deprecation of static RSA and finite-field DH key exchange and discouragement of static ECDH. The reviewed resource flags do not make the static DH/ECDH entries ordinarily negotiable.

Accordingly, the retained legacy entries should be understood as protocol-identity/debugging data, not as a recommendation to negotiate those suites. No immediate cipher-suite resource-table change is indicated by this pass.

### Follow-up observation: ClientHello advertisement mask

One implementation detail remains worth checking separately. The ClientHello construction path uses a mask containing both `tls_flag_secure` and `tls_flag_support`, while the server-side candidate selection explicitly requires `tls_flag_support`.

That distinction may be intentional—for example, to advertise a broader diagnostic or compatibility set—but it should be reconciled with the intended meaning of the flags. The current review records this as a policy-consistency question, not as a confirmed vulnerability or an RFC violation.

### Review conclusion

For this revision, the important security property is the separation between:

1. **Identifier recognition** — a cipher-suite code can be named and inspected.
2. **Resource support** — `tls_flag_support` controls whether it enters the ordinary supported set.
3. **Security recommendation** — `tls_flag_secure` distinguishes the recommended subset.
4. **Diagnostic override** — explicitly enabled debug behavior may relax normal restrictions.

This separation is a useful part of the advisor architecture and should remain explicit in future resource-table reviews.

References:

- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996)
- [RFC 9852 — Updated TLS recommendations](https://www.rfc-editor.org/rfc/rfc9852)
- [RFC 10015 — TLS 1.2 and DTLS 1.2 security updates](https://www.rfc-editor.org/rfc/rfc10015)
- `sdk/net/tls/tls_advisor.hpp`
- `sdk/net/tls/advisor/resource_ciphersuite.cpp`
- `sdk/net/tls/advisor/resource.cpp`
- `sdk/net/tls/protection/tls_protection_context.cpp`
- `sdk/net/tls/tls/extension/tls_extension_supported_versions.cpp`

## Related source documentation

- `sdk/crypto/advisor/README.md`
- `sdk/crypto/advisor/crypto_advisor.md`
- `sdk/net/tls/README.md`
- `sdk/net/tls/advisor/README.md`
- `sdk/crypto/basic/`
- `sdk/net/tls/`
- `test/testcase/crypto/advisor/`
- `test/testcase/tls/`

## Review status

This document reviews the advisor architecture as of revision 1124. It retains the earlier revision-1097 observations as historical context and includes the TLS resource-policy assessment in the same revision-1124 review baseline. The review distinguishes identifier recognition, support eligibility, security recommendation, and diagnostic override. The RFC cross-check found no immediate cipher-suite table change required; the ClientHello advertisement-mask distinction remains a follow-up policy question. Future revisions may add or reorganize resource tables, but the separation between protocol identity and cryptographic identity remains the central architectural point.

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1124                                │
│ Documented with GPT-6                        │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
