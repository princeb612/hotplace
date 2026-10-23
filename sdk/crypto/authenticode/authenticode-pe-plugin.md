# Authenticode PE Plugin

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

`authenticode_plugin_pe` implements the PE-specific part of Authenticode verification. It recognizes Portable Executable files, locates and extracts the security-directory certificate data, calculates the Authenticode image digest, and exposes separate PE checksum operations.

## 2. Data Model

The PE plugin consumes an open `file_stream` and interprets the mapped bytes as a PE image. Its key intermediate values are:

| Data | Meaning |
|---|---|
| DOS header (`IMAGE_DOS_HEADER`) | Validates the `MZ` signature and provides `e_lfanew`, the offset to the NT headers. |
| NT headers (`IMAGE_NT_HEADERS`) | Validates the `PE\0\0` signature and exposes the optional header. |
| Optional header / security directory | Supplies the certificate-table file offset and byte size. The security directory's address is a file offset, not a normal RVA. |
| Certificate-table range | Offset and size used to extract the embedded Authenticode payload. |
| Authenticode payload (`binary_t`) | Certificate-table bytes returned to the verifier for PKCS#7 decoding. |
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

The plugin selects the PE32 or PE32+ optional-header layout, reads `DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]`, and uses its file offset and size as the certificate-table range. It validates the file range before returning the bytes. The verifier then passes these bytes to OpenSSL for PKCS#7 decoding. The plugin's range-returning overload exposes the location; the binary-output overload reads that range into the payload object.

### 3.3 Calculate the Authenticode image digest

The digest path uses the selected hash algorithm and PE layout rather than hashing the entire file as one continuous byte sequence. It accounts for the `CheckSum` field and the certificate-table range according to the Authenticode image-hashing rules. The resulting digest is compared by the verifier with the expected digest in `SpcIndirectDataContent`; the plugin itself does not decide whether the signer or certificate chain is trusted.

### 3.4 Read and update the PE checksum

`read_checksum()`, `calc_checksum()`, and `update_checksum()` form a separate utility path over the PE `CheckSum` field. They support reading the stored value, calculating a checksum, and updating the field. These operations are not substitutes for the cryptographic Authenticode digest and are not required to establish signer trust.

### Example from the source applet

The associated applet is `test/applet/authenticode/sample.cpp`. It passes a PE file to `authenticode_verifier::verify()`, which selects this plugin and compares the plugin's calculated digest with the digest in `SpcIndirectDataContent`. The sample also supplies `trust.crt` for certificate trust configuration. No applet execution was performed as part of this documentation pass.

- [`README.md`](README.md) — overall module map and flow.
- [`authenticode_verifier.md`](authenticode_verifier.md) — orchestration and signer/trust verification.
- `authenticode_plugin.hpp/.cpp` — format-independent interface.
- `authenticode_plugin_pe.hpp/.cpp` — PE implementation.
- [`../../../test/applet/authenticode/sample.cpp`](../../../test/applet/authenticode/sample.cpp) — end-to-end sample.

## 5. Relationships

### Implementation and test sources

- `authenticode_plugin.hpp`, `authenticode_plugin.cpp`, `authenticode_plugin_pe.hpp`, `authenticode_plugin_pe.cpp`.
- PE structures and the security-directory index are interpreted in the implementation; consult the source for exact offset and bounds handling.

### Development Notes (for maintainer review)

- The interface's comments mention PE, MSI, and Cabinet engines, and revision history records a refactor that split those engines. This document describes the concrete PE implementation only; it does not claim MSI/Cabinet support in this directory.
- The plugin includes writing and separated-file hooks in its API surface. Keep API presence distinct from what the current PE implementation actually supports.

## 6. References

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — PE headers and certificate-table layout.
- [Microsoft Authenticode PE Image Hashing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures) — Authenticode image digest construction.
- [RFC 5652: Cryptographic Message Syntax (CMS)](https://www.rfc-editor.org/rfc/rfc5652) — SignedData and signer information.
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) — certificate-path and CRL concepts.
- [RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161) — standards-based timestamp tokens, distinct from the narrow signingTime exception currently described in the module documentation.
