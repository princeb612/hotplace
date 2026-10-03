# Crypto Advisor, TLS Advisor, and Backend Identity

## Review scope

This review describes the relationship between `sdk/crypto/advisor`, `sdk/net/tls/advisor`, and the OpenSSL-facing crypto layer as they exist in revision 1096.

The important distinction is that these are **two related vocabulary/metadata layers**, not a single generic dictionary:

- `crypto_advisor` describes cryptographic identities, algorithms, parameters, aliases, and backend mappings.
- `tls_advisor` describes protocol identifiers used by TLS, DTLS, and QUIC.
- OpenSSL is a backend representation used by the crypto implementation and by the advisor mapping layer; it is not the conceptual owner of either vocabulary.

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

Revision 1096 makes the TLS side broader than a TLS cipher-suite table.

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

This is one reason the advisor layer belongs in the cross-cutting architecture review: its information is consumed by several otherwise separate areas rather than being local to `sdk/crypto`.

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

## 12. Why this is a useful review boundary

The advisor layer is easy to misunderstand if each file is read independently. The interesting part is not the individual lookup function; it is the fact that hotplace maintains several identifier vocabularies and translates between them.

The cross-cutting relationship is therefore:

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

## Related source documentation

- `sdk/crypto/advisor/README.md`
- `sdk/crypto/advisor/crypto_advisor.md`
- `sdk/net/tls/README.md`
- `sdk/net/tls/tls_advisor.md`
- `sdk/crypto/basic/`
- `sdk/net/tls/`
- `test/testcase/crypto/advisor/`
- `test/testcase/tls/`

## Review status

Revision 1096 provides enough structure to distinguish the two advisor domains clearly. Future revisions may add or reorganize resource tables, but the architectural distinction should remain useful as long as protocol identifiers and cryptographic identities remain separate concerns.

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1096                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
