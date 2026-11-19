# Authenticode PE Plugin

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

## 1. Role

`authenticode_plugin_pe` implements the PE-specific part of Authenticode verification. It recognizes Portable Executable files, locates and extracts the security-directory certificate data, calculates the Authenticode image digest, and exposes separate PE checksum operations.

## 2. Data Model

The PE plugin consumes an open `file_stream` and interprets the mapped bytes as a PE image. Its key intermediate values are:

| Data | Meaning |
|---|---|
| DOS header (`IMAGE_DOS_HEADER`) | Validates the `MZ` signature and provides `e_lfanew`, the offset to the NT headers. |
| NT headers (`IMAGE_NT_HEADERS`) | Validates the `PE\0\0` signature and exposes the optional header. |
| Optional header / security directory | Supplies the certificate-table file offset and byte size. The security directory's address is a file offset, not a normal RVA. |
| Certificate-table range | Offset and size used to extract the embedded Authenticode payload. |
| Authenticode payload (`binary_t`) | Payload bytes from the first `WIN_CERTIFICATE` record returned to the verifier for PKCS#7 decoding; the binary-output overload does not return/iterate the entire certificate-table range. |
| Digest algorithm and output (`binary_t`) | Caller-selected hash algorithm and calculated Authenticode image digest. |
| PE `CheckSum` value | Separate 32-bit header checksum read, calculated, or updated by checksum APIs. |

The plugin is a format adapter: it understands PE layout and returns bytes or digest output, while the verifier decides how those outputs participate in PKCS#7 and trust verification. The PE checksum is not the Authenticode image digest.

## 3. Behavior Model

### 3.1 Recognize a PE image

```text
file_stream
  ├─ ensure open
  ├─ begin_mmap() if not already mapped
  ├─ require enough bytes for IMAGE_DOS_HEADER
  ├─ check e_magic == IMAGE_DOS_SIGNATURE ("MZ")
  ├─ bounds-check e_lfanew + NT header size
  └─ check NT signature == IMAGE_NT_SIGNATURE ("PE\0\0")
       └─ true / false
```

The recognition routine rejects null, unopened, undersized, or incorrectly signed inputs. Recognition does not prove every PE offset is valid; extraction and digest calculation perform their own checks before using the corresponding ranges.

### 3.2 Locate and extract the Authenticode payload

The plugin selects the PE32 or PE32+ optional-header layout, reads `DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]`, and uses its file offset and size as the certificate-table range. The range-returning overload checks that `offset + size` is within the mapped file and exposes the location. The binary-output overload then reads only the first `WIN_CERTIFICATE`, accepts revision 2.0 and `WIN_CERT_TYPE_PKCS_SIGNED_DATA`, and copies `dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate)` bytes. It does not iterate subsequent aligned records, and it does not validate that `dwLength` is at least the header size or bounded by the directory size before subtracting/copying. The verifier passes the extracted payload to OpenSSL for PKCS#7 decoding.

### 3.3 Calculate the Authenticode image digest

The current digest path performs a linear hash over the file prefix ending at the certificate-table file offset. It hashes bytes before the PE `CheckSum`, skips the four-byte checksum field, hashes up to the security-directory entry, skips that eight-byte entry, then hashes from after the entry up to the certificate-table offset. It does not hash bytes at or after that offset and does not iterate PE section headers or use the certificate-table size to resume hashing after the table. This is the exact current source behavior; it should not be described more broadly as a complete section-by-section implementation of every Authenticode image-hashing case. The PE plugin checks `hash.open()` but ignores `hash.init()`, `hash.update()` and `hash.finalize()` return values. The resulting digest is compared by the verifier with the expected digest in `SpcIndirectDataContent`; the plugin itself does not decide whether the signer or certificate chain is trusted.

### 3.4 Read and update the PE checksum

`read_checksum()`, `calc_checksum()`, and `update_checksum()` form a separate utility path over the PE `CheckSum` field. `read_checksum()` reads the stored value; `calc_checksum()` computes a PE checksum with the field treated as zero; `update_checksum()` computes and writes that value. These operations are not substitutes for the cryptographic Authenticode digest and are not required to establish signer trust. Their input validation is not uniform: `read_checksum()` checks the NT-header range but not the complete optional-header range, while `calc_checksum()` and `update_checksum()` do not perform equivalent NT/optional-header bounds checks before dereferencing those structures.

### Example from the source applet

The associated applet is `test/applet/authenticode/sample.cpp`. It passes a PE file to `authenticode_verifier::verify()`, which selects this plugin and compares the plugin's calculated digest with the digest in `SpcIndirectDataContent`. The sample also supplies `trust.crt` for certificate trust configuration. No applet execution was performed as part of this documentation pass.

- [`README.md`](README.md) — overall module map and flow.
- [`authenticode_verifier.md`](authenticode_verifier.md) — orchestration and signer/trust verification.
- `authenticode_plugin.hpp/.cpp` — format-independent interface.
- `authenticode_plugin_pe.hpp/.cpp` — PE implementation.
- [`../../../test/applet/authenticode/sample.cpp`](../../../test/applet/authenticode/sample.cpp) — end-to-end sample.

## 4. Relationships
### Implementation and test sources

- `authenticode_plugin.hpp`, `authenticode_plugin.cpp`, `authenticode_plugin_pe.hpp`, `authenticode_plugin_pe.cpp`.
- PE structures and the security-directory index are interpreted in the implementation; consult the source for exact offset and bounds handling.

### Development Notes (for maintainer review)

- The interface's comments mention PE, MSI, and Cabinet engines, and revision history records a refactor that split those engines. This document describes the concrete PE implementation only; it does not claim MSI/Cabinet support in this directory.
- The plugin includes writing and separated-file hooks in its API surface. Keep API presence distinct from what the current PE implementation actually supports. `separated()` returns false, and both separated-file methods return `not_available`. The current `write_authenticode()` truncates the file and updates the security-directory size, but its assignments to `WIN_CERTIFICATE.dwLength`, `wRevision` and `wCertificateType` are commented out; it also does not add record alignment. Treat this as an incomplete write path, not a complete Authenticode signing/rewriting implementation.

## 5. References
- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — PE headers and certificate-table layout.
- [Microsoft Authenticode PE Image Hashing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures) — Authenticode image digest construction.
- [RFC 5652: Cryptographic Message Syntax (CMS)](https://www.rfc-editor.org/rfc/rfc5652) — SignedData and signer information.
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) — certificate-path and CRL concepts.
- [RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161) — standards-based timestamp tokens, distinct from the narrow signingTime exception currently described in the module documentation.
