# Authenticode PE Plugin

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

`authenticode_plugin_pe` implements the PE-specific part of Authenticode verification. It recognizes Portable Executable files, locates and extracts the security-directory certificate data, calculates the Authenticode image digest, and exposes separate PE checksum operations.

## 2. Model

The abstract `authenticode_plugin` interface separates file-format operations from verifier orchestration. The PE plugin supplies the concrete implementation:

```text
authenticode_verifier
  ↓ selects engine using is_kind_of()
authenticode_plugin interface
  ↓
authenticode_plugin_pe
  ├─ recognize DOS / NT PE headers
  ├─ read or write security-directory certificate data
  ├─ calculate Authenticode image digest
  └─ read / calculate / update PE CheckSum
```

## 3. Important behavior and lifetime

- PE detection is based on DOS/NT header information. Authenticode data is located via the PE optional header's security directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`).
- Extracted certificate-table data is returned as binary data for the verifier to decode as PKCS#7 signed content. The plugin also exposes a write operation, which is separate from the usual verification path.
- `digest()` implements the Authenticode image-hashing layout, treating the PE checksum field and certificate-table region specially. It is not equivalent to hashing the entire file from byte zero to EOF.
- `read_checksum()`, `calc_checksum()`, and `update_checksum()` operate on the PE `CheckSum` field; this checksum is distinct from the cryptographic Authenticode image digest.
- The plugin's `separated()` result is false. The generic interface contains separated-file methods, but those methods do not establish that this PE plugin implements detached/separated signatures.

## 4. Example from the source tests

The associated applet is `test/applet/authenticode/sample.cpp`. It passes a PE file to `authenticode_verifier::verify()`, which selects this plugin and compares the plugin's calculated digest with the digest in `SpcIndirectDataContent`. The sample also supplies `trust.crt` for certificate trust configuration. No applet execution was performed as part of this documentation pass.

## 5. Relationships

- [`README.md`](README.md) — overall module map and flow.
- [`authenticode_verifier.md`](authenticode_verifier.md) — orchestration and signer/trust verification.
- `authenticode_plugin.hpp/.cpp` — format-independent interface.
- `authenticode_plugin_pe.hpp/.cpp` — PE implementation.
- [`../../../test/applet/authenticode/sample.cpp`](../../../test/applet/authenticode/sample.cpp) — end-to-end sample.

## 6. References

- `authenticode_plugin.hpp`, `authenticode_plugin.cpp`, `authenticode_plugin_pe.hpp`, `authenticode_plugin_pe.cpp`.
- PE structures and the security-directory index are interpreted in the implementation; consult the source for exact offset and bounds handling.

### Development Notes (for maintainer review)

- The interface's comments mention PE, MSI, and Cabinet engines, and revision history records a refactor that split those engines. This document describes the concrete PE implementation only; it does not claim MSI/Cabinet support in this directory.
- The plugin includes writing and separated-file hooks in its API surface. Keep API presence distinct from what the current PE implementation actually supports.
