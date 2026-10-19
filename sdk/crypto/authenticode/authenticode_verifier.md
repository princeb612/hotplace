# Authenticode Verifier

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

`authenticode_verifier` is the orchestration layer for the PE Authenticode verification flow. It manages a verification context, selects a registered format engine, compares the embedded Authenticode digest with a format-specific digest, and asks OpenSSL to verify PKCS#7 signer and certificate information.

## 2. Model

`authenticode_context_t` carries the registered engines, trusted signer/certificate material, CRL-related state and paths/options, proxy/configuration fields, and synchronization for shared CRL state. The public lifecycle is:

```text
authenticode_verifier
  → open(context)
  → configure trust / options
  → verify(context, filename, flags, result)
  → close(context)
```

The principal verification path is:

1. Open the target through `file_stream` and select an engine with `is_kind_of()`.
2. Extract the Authenticode payload and decode it as PKCS#7 using OpenSSL.
3. Read the digest algorithm and expected digest from `SpcIndirectDataContent`.
4. Ask the selected plugin to calculate the file-format-specific digest.
5. Return a digest failure if the values differ; otherwise proceed to PKCS#7 signer/certificate verification.

```text
format plugin → signature payload → PKCS#7 / SpcIndirectDataContent
       │                                  │
       └── calculate image digest ────────┤ compare
                                          ▼
                                  signer / trust checks
```

## 3. Important behavior and lifetime

- The caller owns the context lifecycle: open, configure, verify, close. The applet shows this sequence explicitly.
- Trust material is added through `add_trusted_rootcert()`. The implementation builds an OpenSSL `X509_STORE` and uses `PKCS7_verify()` for the signer/certificate side of verification. Exact acceptance depends on configured trust and verification options; a successful embedded-digest comparison alone is not a complete signature/trust result.
- PE hashing is delegated to `authenticode_plugin_pe`; the verifier does not hash the whole PE file as an opaque byte sequence.
- The `flag_separated` flag enters the verifier's separated-file handling path, but the PE plugin itself reports that it is not a separated engine. Do not infer detached-signature support for PE from the generic flag or interface alone.
- CRL distribution points are parsed from certificates and CRL download/cache logic is present. The applet sets `authenticode_ctrl_t::set_crl` to zero, so the sample does not exercise CRL downloading. This documentation pass does not certify the completeness of revocation checking.
- The CRL URL-to-cache mapping uses `sdk/io/string::split_url()`.

## 4. Example from the source tests

In `test/applet/authenticode/sample.cpp`, `test1()` creates a verifier, opens a context, disables CRL downloading, registers `trust.crt`, invokes `verify()` on the user-selected input file, then closes the context in the cleanup path. The applet reports the return code; it is a runnable sample, not evidence that the test was executed in this documentation pass.

## 5. Relationships

- [`README.md`](README.md) — module boundary and end-to-end flow.
- [`authenticode-pe-plugin.md`](authenticode-pe-plugin.md) — format-specific extraction and digest computation.
- `authenticode_verifier.hpp/.cpp` — public API and implementation.
- `sdk.hpp/.cpp` — CRL distribution-point helper.
- [`../../../io/string/`](../../io/string/) — URL decomposition for CRL cache paths.
- [`../../../test/applet/authenticode/sample.cpp`](../../../test/applet/authenticode/sample.cpp) — concrete API usage.

## 6. References

- `authenticode_verifier.hpp`, `authenticode_verifier.cpp`, `sdk.hpp`, `sdk.cpp`.
- OpenSSL APIs used by the source: `d2i_PKCS7_bio()`, `PKCS7_verify()`, `X509_STORE`.

### Development Notes (for maintainer review)

- `authenticode_verifier.hpp` has a source comment describing CRL revocation verification as temporarily disabled and file-download-related. The current implementation contains CRL configuration and download/cache code, so this note is a reminder to audit behavior and comments together rather than to claim the feature is wholly absent.
- Existing code comments include CRL test paths, cache handling, and commented-out error cases. They have not been removed or reclassified by this documentation update.
