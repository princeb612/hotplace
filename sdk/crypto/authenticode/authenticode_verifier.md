# Authenticode Verifier

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

## 1. Role

`authenticode_verifier` is the orchestration layer for the PE Authenticode verification flow. It manages a verification context, selects a registered format engine, compares the embedded Authenticode digest with a format-specific digest, and asks OpenSSL to verify PKCS#7 signer and certificate information.

## 2. Data Model

`authenticode_context_t` is the state object passed through the public API. It holds registered engine references, trusted-certificate configuration, verification options, CRL retrieval settings, a URI-keyed CRL cache, and locks protecting shared state. The caller receives the opaque context from `open()` and releases it through `close()`.

The verification call joins four representations:

| Representation | Key data | Purpose |
|---|---|---|
| Target file | `file_stream`, PE headers, security-directory offset/size | Identify the format and provide bytes to the PE engine. |
| Extracted signature | Certificate-table `binary_t`, decoded `PKCS7*` | Carry signed data and signer/certificate material. |
| Signed digest description | `SpcIndirectDataContent`, digest algorithm, expected digest | State which image digest the signer signed. |
| Calculated digest | Plugin-produced `binary_t` | Represent the file's Authenticode digest for comparison. |

The trust path uses additional state: configured trusted certificate files, signer certificates from PKCS#7, CRL distribution-point URIs, decoded `X509_CRL*` objects, and a temporary `X509_STORE`. A URI in a certificate, a cached CRL, a successfully decoded CRL, and a successful revocation decision are different states; none should be documented as equivalent.

The PE plugin owns PE-layout interpretation and produces the signature payload and calculated digest. The verifier owns the sequence that joins those values to PKCS#7 decoding and certificate verification. The PE checksum field is separate from the cryptographic Authenticode image digest.

## 3. Behavior Model

### 3.1 Public lifecycle

```text
authenticode_verifier verifier
  │
  ├─ open(&context)
  ├─ set(context, options...)
  ├─ add_trusted_rootcert(context, cert_file, path)
  ├─ verify(context, filename, flags, result)
  └─ close(context)
```

The applet in `test/applet/authenticode/sample.cpp` demonstrates the call sequence. The context is caller-managed; the stream, decoded signature, store and verification objects are used by the implementation during verification. Always close the context on the cleanup path, including when verification fails.

### 3.2 Select the file-format engine

`verify()` opens the target through `file_stream` and asks the engines registered in the context to recognize it using `is_kind_of()`. The PE plugin checks the DOS signature, validates that the NT-header offset is within the mapped file, and checks the NT signature. If no engine recognizes the file, the verifier cannot proceed with format-specific extraction.

### 3.3 Extract and compare the signed image digest

1. The selected plugin locates the PE security-directory certificate table and returns its bytes.
2. OpenSSL decodes the payload as PKCS#7 SignedData.
3. The verifier reads `SpcIndirectDataContent` to obtain the expected digest and algorithm.
4. The plugin calculates the Authenticode image digest using the PE hashing layout, which handles the PE checksum field and certificate-table region specially.
5. A digest mismatch terminates the verification path. Only a match proceeds to `verify_pkcs7()`.

```text
PE file ──► PE plugin ──► certificate-table payload ──► PKCS#7
   │                                                  │
   └──────────────► Authenticode image digest ◄───────┘
                              │
                     compare expected digest
                              │ match
                              ▼
                      verify_pkcs7()
```

The PE checksum API is not a substitute for this cryptographic digest comparison.

**Implementation detail:** `authenticode_verifier::verify()` calls the selected engine's `digest()` method without checking its returned `return_t`. Therefore, a digest-calculation error is not necessarily propagated as that original error code; the later digest comparison may determine the visible failure instead.

### 3.4 Assemble trust and revocation inputs

`verify_pkcs7()` checks that the decoded object is SignedData, enumerates signer and embedded certificates, and calls `get_crl()` to gather CRLs for their distribution-point URIs. When enabled, retrieval checks the context cache and local path before it may invoke `wget` through the project's `process` abstraction. Downloaded or local bytes must decode as `X509_CRL` before being added to the per-call CRL map.

The verifier creates an `X509_STORE`, loads default paths and configured trusted certificate files, installs `verify_callback`, enables `X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`, adds successfully decoded CRLs, and calls `PKCS7_verify()`. CRL retrieval is preparation; it is not itself evidence that revocation validation passed.

### 3.5 Interpret the result and limitations

The API returns a `return_t` error code and writes a coarse `verify_ok` / `verify_fail` status to `result`. The failure boundary may be file/format recognition, extraction, PKCS#7 decoding, digest comparison, CRL preparation, or signature/trust verification. Do not interpret every failure as a cryptographic signature mismatch.

The PE engine reports `separated() == false`; the generic `flag_separated` and interface hooks do not prove that detached/separated PE signatures are supported. Likewise, a successful digest comparison does not establish signer trust, and CRL retrieval does not guarantee a successful revocation check.

The specific callback exception for an expired signer certificate and its counter-signature `signingTime` handling are documented in [the module README § 3.6](README.md#36-current-signing-time-exception-and-crl-path). That path does not by itself establish full trusted timestamp-token and TSA-chain validation.

### Example from the source applet

In `test/applet/authenticode/sample.cpp`, `test1()` creates a verifier, opens a context, enables CRL downloading, registers `trust.crt`, invokes `verify()` on the user-selected input file, then closes the context in the cleanup path. The applet reports the return code; it is a runnable sample, not evidence that the test was executed in this documentation pass.

- [`README.md`](README.md) — module boundary, end-to-end flow, and the current signing-time/CRL behavior map.
- [`authenticode-pe-plugin.md`](authenticode-pe-plugin.md) — format-specific extraction and digest computation.
- `authenticode_verifier.hpp/.cpp` — public API and implementation.
- `sdk.hpp/.cpp` — CRL distribution-point helper.
- [`../../../io/string/`](../../io/string/) — URL decomposition for CRL cache paths.
- [`../../../test/applet/authenticode/sample.cpp`](../../../test/applet/authenticode/sample.cpp) — concrete API usage.

## 4. Relationships
### Implementation and test sources

- `authenticode_verifier.hpp`, `authenticode_verifier.cpp`, `sdk.hpp`, `sdk.cpp`.
- OpenSSL APIs used by the source: `d2i_PKCS7_bio()`, `PKCS7_verify()`, `X509_STORE`.

### Development Notes (for maintainer review)

- The signing-time exception currently reads a `signingTime` from a PKCS#7 counter-signature attribute and uses it only to override `X509_V_ERR_CERT_HAS_EXPIRED` for the signer certificate at depth zero when the time falls within that certificate's validity interval. The code path shown does not, by itself, establish validation of a trusted timestamp authority or its timestamp-token signature. Do not describe it as complete trusted-timestamp validation.

## 5. References
- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — PE headers and certificate-table layout.
- [Microsoft Authenticode PE Image Hashing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures) — Authenticode image digest construction.
- [RFC 5652: Cryptographic Message Syntax (CMS)](https://www.rfc-editor.org/rfc/rfc5652) — SignedData and signer information.
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) — certificate-path and CRL concepts.
- [RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161) — standards-based timestamp tokens, distinct from the narrow signingTime exception currently described in the module documentation.
