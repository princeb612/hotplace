# Windows Authenticode Verification

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

## 1. Role

`sdk/crypto/authenticode/` implements the project's Authenticode verification path for Windows Portable Executable (PE) files. It extracts the embedded signature material, calculates the PE Authenticode image digest, compares it with the digest described by the signed content, and delegates signer/certificate verification to OpenSSL.

This module is a format-specific verification feature, **not a general-purpose PKI framework**. The current concrete format implementation is PE; the abstract plugin interface still carries hooks associated with separated signatures and other historical file formats.

## 2. Model

| Source unit | Responsibility |
|---|---|
| `authenticode_verifier.hpp/.cpp` | Public verification API, context/options, engine selection, digest comparison, signer/trust verification |
| `authenticode_plugin.hpp/.cpp` | Format-engine interface and shared-reference lifecycle |
| `authenticode_plugin_pe.hpp/.cpp` | PE recognition, certificate-table extraction/writing, Authenticode image digest and PE checksum operations |
| `sdk.hpp/.cpp` | X.509 CRL distribution-point helper and Authenticode-specific OpenSSL support |
| `types.hpp` | Engine identifiers and module-level types |

The main path is: `authenticode_verifier::verify()` opens a `file_stream`, chooses a registered engine using `is_kind_of()`, extracts the signature payload, decodes PKCS#7 signed data, reads `SpcIndirectDataContent`, and asks the PE plugin for the Authenticode image digest. A digest match is followed by PKCS#7 signer/certificate verification.

```text
PE file
  │
  ▼
authenticode_verifier::verify()
  │ engine selection
  ▼
authenticode_plugin_pe
  ├─ identify PE / extract certificate-table payload
  ├─ calculate PE Authenticode image digest
  └─ read / calculate / update PE checksum
  │
  ▼
PKCS#7 SignedData + SpcIndirectDataContent
  │
  ├─ compare embedded digest with calculated digest
  └─ verify signer and certificate chain using OpenSSL
```

## 3. Important behavior and lifetime

- The PE image digest is **not** an ordinary hash of every file byte. PE checksum and certificate-table regions are handled according to the Authenticode hashing layout.
- `authenticode_plugin_pe` owns PE layout knowledge; `authenticode_verifier` owns orchestration and trust configuration.
- `authenticode_context_t` is opened through `authenticode_verifier::open()`, configured, passed to `verify()`, and released with `close()`. Trust roots can be added with `add_trusted_rootcert()`.
- The PE plugin reports `separated() == false`; the interface's separated-file hooks should not be read as proof that this PE implementation verifies detached signatures.
- CRL distribution-point parsing, download/cache configuration, and X.509 store setup are present, but revocation handling needs separate scrutiny before treating it as production-complete. The applet disables CRL downloading.
- The verifier uses OpenSSL PKCS#7/X.509 APIs directly. The wider project's ASN.1 runtime is not a direct dependency of this verification path.

## 4. Example from the source tests

`test/applet/authenticode/sample.cpp` demonstrates the concrete calling sequence: initialize OpenSSL, parse a target file argument, open a verifier context, disable CRL downloading for the sample, add `trust.crt` as trusted root material, call `verify()`, close the context, and report the result. It is an applet/sample rather than a dedicated `test/testcase/crypto/authenticode/` testcase directory.

A typical invocation shown in the source comments is `test-authenticate -v -i /path/to/target.exe`; the target file and `trust.crt` must be supplied in the environment. This documentation pass did not run the applet.

## 5. Relationships

- [`authenticode_verifier.md`](authenticode_verifier.md) — context lifecycle, verification stages, trust and CRL boundaries.
- [`authenticode-pe-plugin.md`](authenticode-pe-plugin.md) — PE parsing, digest exclusions and checksum API.
- [`../../basic/openssl_sdk.hpp`](../basic/openssl_sdk.hpp) — OpenSSL initialization/hash support used by the surrounding crypto layer.
- [`../../../io/stream/`](../../io/stream/) — file access through `file_stream`.
- [`../../../io/string/`](../../io/string/) — CRL URL decomposition through `split_url`.
- [`../../io/asn.1/`](../../io/asn.1/) — broader ASN.1 module; not the direct parser used for this PKCS#7 path.
- [`../../../test/applet/authenticode/`](../../../test/applet/authenticode/) — sample executable and build definition.

## 6. References

- `authenticode.hpp`, `authenticode_verifier.hpp/.cpp`, `authenticode_plugin.hpp/.cpp`, `authenticode_plugin_pe.hpp/.cpp`, `sdk.hpp/.cpp`, `types.hpp`.
- `test/applet/authenticode/README.md`, `sample.cpp`, `CMakeLists.txt`.

### Development Notes (for maintainer review)

- Source comments and revision history record the evolution from Windows SDK verification to OpenSSL and then to a plugin-oriented implementation. Keep this history distinct from the current supported-format claim.
- The plugin interface documents PE, MSI, and Cabinet as historical/intended engine types, but this directory's concrete implementation and this documentation scope are PE-focused.
- CRL download/cache behavior is configurable in code, while source comments describe revocation-related work as temporary or disabled in places. Verify the current behavior and policy before describing revocation checking as complete.
