# Authenticode Verifier

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

## 1. Role

`authenticode_verifier` is the orchestration layer for the PE Authenticode verification flow. It manages a verification context, selects a registered format engine, compares the embedded Authenticode digest with a format-specific digest, and asks OpenSSL to verify PKCS#7 signer and certificate information.

## 2. Data Model

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

## 3. Behavior Model

- The caller owns the context lifecycle: open, configure, verify, close. The applet shows this sequence explicitly.
- Trust material is added through `add_trusted_rootcert()`. The implementation builds an OpenSSL `X509_STORE` and uses `PKCS7_verify()` for the signer/certificate side of verification. Exact acceptance depends on configured trust and verification options; a successful embedded-digest comparison alone is not a complete signature/trust result.
- PE hashing is delegated to `authenticode_plugin_pe`; the verifier does not hash the whole PE file as an opaque byte sequence.
- The `flag_separated` flag enters the verifier's separated-file handling path, but the PE plugin itself reports that it is not a separated engine. Do not infer detached-signature support for PE from the generic flag or interface alone.
- CRL distribution points are parsed from certificates. The verifier attempts to reuse cached/local CRLs and, when enabled, can invoke `wget` through the project's `process` abstraction to retrieve missing files. It configures `X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL` and adds successfully decoded CRLs to the OpenSSL store. Retrieval itself does not establish that revocation checking succeeded.
- The sample in `test/applet/authenticode/sample.cpp` sets `authenticode_ctrl_t::set_crl` to `1`; its comment says to set it to `0` for an air-gapped network.
- The signer-certificate expiry exception and CRL path are separate concerns. The precise current behavior, flow diagram, limitations, and review questions are recorded in [`README.md` § 3.1, “Current signing-time exception and CRL path”](README.md#31-current-signing-time-exception-and-crl-path).

## 4. Relationships

### Implementation and test sources

- `authenticode_verifier.hpp`, `authenticode_verifier.cpp`, `sdk.hpp`, `sdk.cpp`.
- OpenSSL APIs used by the source: `d2i_PKCS7_bio()`, `PKCS7_verify()`, `X509_STORE`.

### Source-test evidence

In `test/applet/authenticode/sample.cpp`, `test1()` creates a verifier, opens a context, enables CRL downloading, registers `trust.crt`, invokes `verify()` on the user-selected input file, then closes the context in the cleanup path. The applet reports the return code; it is a runnable sample, not evidence that the test was executed in this documentation pass.

- [`README.md`](README.md) — module boundary, end-to-end flow, and the current signing-time/CRL behavior map.
- [`authenticode-pe-plugin.md`](authenticode-pe-plugin.md) — format-specific extraction and digest computation.
- `authenticode_verifier.hpp/.cpp` — public API and implementation.
- `sdk.hpp/.cpp` — CRL distribution-point helper.
- [`../../../io/string/`](../../io/string/) — URL decomposition for CRL cache paths.
- [`../../../test/applet/authenticode/sample.cpp`](../../../test/applet/authenticode/sample.cpp) — concrete API usage.

### Development Notes (for maintainer review)

- `authenticode_verifier.hpp` retains a source comment describing CRL revocation verification as temporarily disabled and file-download-related. The current implementation contains CRL configuration and download/cache code; keep source comments and runtime behavior aligned during future maintenance.
- The signing-time exception currently reads a `signingTime` from a PKCS#7 counter-signature attribute and uses it only to override `X509_V_ERR_CERT_HAS_EXPIRED` for the signer certificate at depth zero when the time falls within that certificate's validity interval. The code path shown does not, by itself, establish validation of a trusted timestamp authority or its timestamp-token signature. Do not describe it as complete trusted-timestamp validation.
