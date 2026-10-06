# Authenticode Verification Architecture

## Review thesis

**Authenticode is architecturally interesting because one verification decision must keep PE-specific image rules, signed-data verification, and certificate trust distinct while still producing one coherent verification result.**

The scope is deliberately narrow: this is a review of the implementation path used to verify Windows Authenticode signatures in PE files. It is not a general-purpose PKI or digital-certificate study.

## Source Baseline

- Source tree: hotplace revision 1097
- Primary area: `sdk/crypto/authenticode/`
- Practical sample: `test/applet/authenticode/sample.cpp`

## 1097 review pass

This document was rechecked as part of the revision-1097 architecture review. No material revision-1097 architectural change was identified in this axis; the document therefore preserves the established 1096 relationship model rather than inventing a new revision-specific change.

## 1. Verification as a composition of distinct responsibilities

The verifier is not one large cryptographic operation. It composes several responsibilities that have different meanings: the PE plugin determines what image bytes are covered by Authenticode, the signed-data path determines what digest was signed, and the trust path determines whether the signer can be trusted.

```text
                         Windows PE file
                               │
                               ▼
                    authenticode_plugin_pe
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
          PE structure                  certificate table
                 │                           │
                 ▼                           ▼
        Authenticode image digest          PKCS#7
                 │                           │
                 └─────────────┬─────────────┘
                               ▼
                    authenticode_verifier
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
                 digest              signer / trust
                    │                     │
                    └──────────┬──────────┘
                               ▼
                         OpenSSL APIs
```

The resulting verification path combines:

- `sdk/io/stream` for file access
- PE-specific binary parsing
- cryptographic digest facilities
- PKCS#7/X.509 verification through OpenSSL
- ASN.1 concepts without routing the implementation through hotplace's ASN.1 runtime
- URL handling for CRL distribution points

## 2. Plugin Boundary

The central architectural decision is that the verifier does not directly contain PE parsing logic.

```text
authenticode_verifier
        │
        │ is_kind_of()
        ▼
authenticode_plugin
        │
        ▼
authenticode_plugin_pe
   ├── detect PE
   ├── extract certificate data
   ├── calculate Authenticode digest
   └── PE checksum operations
```

`authenticode_plugin` is the format-independent engine interface.

`authenticode_plugin_pe` provides the PE-specific implementation.

The verifier can therefore perform the common verification orchestration without embedding DOS/NT header and PE security-directory details into the verifier itself.

The source also contains engine identifiers for MSI and Cabinet paths. Those interfaces reflect the broader plugin-oriented design, while the current documented implementation is focused on PE verification.

## 3. PE Digest Is Not a Whole-File Hash

A central detail is that Authenticode verification does not simply hash the PE file byte-for-byte.

The PE plugin's `digest()` follows the Authenticode image-digest rules and treats PE metadata specially, including:

- the PE checksum field
- the security directory
- the certificate-table area

Conceptually:

```text
PE file
  │
  ├── ordinary image regions ────────┐
  ├── PE CheckSum field ── special ──┤
  ├── security directory ── special ─┤
  └── certificate table ── excluded ─┘
                                     │
                                     ▼
                          Authenticode image digest
```

That calculated digest is later compared with the digest carried by the signed Authenticode data.

This separation is important because it keeps the **file-format rule** in `authenticode_plugin_pe`, rather than making the generic verifier understand PE hashing details.

## 4. PKCS#7 and `SpcIndirectDataContent`

After extraction, the certificate-table data is decoded as PKCS#7.

The relevant flow is:

```text
PE certificate table
        │
        ▼
      PKCS#7
        │
        ▼
SpcIndirectDataContent
        │
        ▼
embedded digest algorithm + expected digest
        │
        ▼
compare with PE Authenticode image digest
```

The verifier uses OpenSSL's PKCS#7/X.509 APIs directly for this path.

This is an important architectural distinction:

```text
hotplace ASN.1 implementation
        │
        ├── parser
        ├── semantic construction
        ├── runtime
        └── constraints

Authenticode verification
        │
        └── OpenSSL PKCS#7 / X.509 APIs
```

The Authenticode code therefore **uses ASN.1/PKCS#7 as a protocol/data-format concept**, but it does not currently depend on `sdk/io/asn.1` for decoding the signed certificate structure.

This should not be documented as if Authenticode were another consumer of the hotplace ASN.1 runtime.

## 5. Verification Orchestration

The main lifecycle is:

```text
authenticode_verifier
      │
      ├── open()
      │     └── initialize verification state / engines
      │
      ├── configure trust / options
      │
      ├── verify()
      │     │
      │     ├── open file through file_stream
      │     ├── select engine
      │     ├── extract Authenticode data
      │     ├── decode PKCS#7
      │     ├── obtain SpcIndirectDataContent digest
      │     ├── calculate PE Authenticode digest
      │     ├── compare digests
      │     └── verify signer / certificate chain
      │
      └── close()
```

The digest comparison is a meaningful checkpoint:

```text
embedded digest
       │
       │ compare
       ▼
calculated PE digest
       │
   ┌───┴────┐
   │        │
 match   mismatch
   │        │
   ▼        ▼
continue  digest_failure
```

Certificate trust verification is therefore not a substitute for validating that the signed digest actually describes the PE image being checked.

## 6. Trust and CRL Handling

The verifier maintains trust-related state for:

- trusted signers
- trusted root certificates
- certificate/CRL configuration
- CRL cache/path state
- proxy-related options

The PKCS#7 verification path builds an OpenSSL `X509_STORE` from configured trust material.

CRL distribution points create a separate connection to the string/URL subsystem:

```text
certificate
    │
    ▼
CRL distribution point
    │
    ▼
sdk/io/string::split_url()
    │
    ▼
local CRL/cache representation
```

The current source treats CRL download/cache handling as an evolving area. The sample applet disables CRL download for its practical verification path.

This is a good example of why the review layer should record **actual implementation boundaries and current status**, rather than presenting every surrounding facility as a finished general-purpose framework.

## 7. Reusing the existing file-I/O boundary

The PE file itself is accessed through the existing stream layer.

```text
authenticode_verifier
        │
        ▼
    file_stream
        │
        ▼
       PE
```

The connection is small but architecturally useful: Authenticode does not introduce a private file-I/O abstraction merely to process PE files. The verifier can concentrate on verification policy while the existing stream abstraction remains responsible for opening and reading the file.

## 8. Relation to the Crypto Layer

The dependency direction is better represented as:

```text
                 Authenticode verification
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
       PE rules        PKCS#7/X.509       digest
          │                │                │
          ▼                ▼                ▼
 authenticode_pe        OpenSSL        crypto facilities
```

This differs from `crypto_advisor`.

`crypto_advisor` provides identity/resource information such as digest, key, curve, signature and protocol-related identifiers.

Authenticode instead consumes concrete cryptographic and certificate functionality as part of a verification workflow.

So:

```text
crypto_advisor
    → "what algorithm / identifier is this?"

Authenticode
    → "verify this signed PE according to Authenticode rules"
```

They are related, but they solve different architectural problems.

## 9. Relation to the ASN.1 Layer

There are two distinct relationships:

```text
                ASN.1 / PKCS#7
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
hotplace ASN.1 runtime     OpenSSL PKCS#7/X.509
          │                     │
          │                     ▼
          │               Authenticode
          │
          ▼
ASN.1 study / parser / runtime
```

The first branch is hotplace's own ASN.1 implementation and study path.

The second is the actual Authenticode verification implementation.

The review should preserve this distinction because otherwise the source-tree relationship can easily be misunderstood as:

```text
ASN.1 parser → Authenticode verifier
```

which is not the current implementation path.

## 10. Development History

The Authenticode source records a progression roughly along these lines:

```text
Windows SDK based verification
            │
            ▼
     OpenSSL implementation
            │
            ▼
   plugin-oriented verifier
            │
            ▼
        PE-focused path
```

The current plugin boundary therefore appears to be a consequence of implementation evolution rather than an abstract framework introduced in isolation.

The source also retains MSI/Cabinet engine identifiers and plugin concepts, but the present documented implementation is centered on PE.

## 11. Practical Verification Path

The available applet demonstrates the intended usage more clearly than a hypothetical generic API example.

```text
test/applet/authenticode/sample.cpp
             │
             ├── target executable
             ├── trust.crt
             ├── CRL download disabled
             └── separated-signature flag
                       │
                       ▼
               authenticode_verifier
                       │
                       ▼
                    verify()
```

There is no dedicated `test/testcase/crypto/authenticode/` tree in the current source.

That means the applet is currently the most direct executable example of the subsystem.

## 12. Architectural relationships

Authenticode can be placed into the wider hotplace map as follows:

```text
                        hotplace
                           │
          ┌────────────────┼─────────────────┐
          │                │                 │
         io              crypto             ASN.1
          │                │                 │
    ┌─────┴─────┐          │            parser/runtime
    │           │          │                 │
file_stream  string        │                 │
    │       split_url      │                 │
    │           │          │                 │
    └─────┬─────┘          │                 │
          │                │                 │
          ▼                ▼                 │
       PE file       crypto / OpenSSL        │
          │                │                 │
          └───────┬────────┘                 │
                  ▼                          │
          Authenticode verifier              │
                  │                          │
          ┌───────┴────────┐                 │
          ▼                ▼                 │
       PE rules        PKCS#7/X.509          │
                           │                 │
                           └───────┬─────────┘
                                   │
                              ASN.1 concept
```

The important distinction is between **direct implementation responsibilities** and **conceptual relationships**. `file_stream`, PE-specific digest rules, and OpenSSL PKCS#7/X.509 APIs participate directly in the verification path. ASN.1 is relevant because PKCS#7 and related structures are ASN.1-based, but the current Authenticode implementation does not route those structures through hotplace's ASN.1 runtime.

## 13. Current Status

As of revision 1097:

- PE Authenticode verification is the documented implementation scope.
- The verifier uses a plugin-oriented architecture.
- PE-specific digest calculation is isolated in `authenticode_plugin_pe`.
- PKCS#7/X.509 processing uses OpenSSL APIs directly.
- Trust roots/signers and CRL-related state are handled by the verifier context.
- `file_stream` and URL splitting are concrete cross-module dependencies.
- MSI/Cabinet engine identifiers remain in the source, but are outside the current PE-focused documentation scope.
- There is no dedicated Authenticode testcase directory; the sample applet is the practical executable example.
- This subsystem should not be described as a general-purpose PKI implementation.

## Related Source

- `sdk/crypto/authenticode/README.md`
- `sdk/crypto/authenticode/authenticode_verifier.hpp`
- `sdk/crypto/authenticode/authenticode_verifier.cpp`
- `sdk/crypto/authenticode/authenticode_plugin.hpp`
- `sdk/crypto/authenticode/authenticode_plugin_pe.hpp`
- `sdk/crypto/authenticode/authenticode_plugin_pe.cpp`
- `sdk/crypto/authenticode/sdk.cpp`
- `sdk/io/stream/file_stream.*`
- `sdk/io/string/*`
- `test/applet/authenticode/sample.cpp`

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1097                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
