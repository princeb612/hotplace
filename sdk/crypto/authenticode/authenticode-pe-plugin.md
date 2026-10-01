# Authenticode PE Plugin

`authenticode_plugin_pe` contains the file-format-specific portion of Authenticode verification for Windows Portable Executable files.

## PE detection and extraction

The plugin recognizes PE files through their DOS/NT headers and extracts the Authenticode certificate-table data from the PE optional header's security directory.

The extracted data is returned as a binary blob for the verifier to decode as PKCS#7 signed data.

The implementation also supports writing Authenticode data back into the PE certificate area. This is part of the plugin API but is separate from the normal verification path.

## Authenticode image digest

`digest()` maps the PE file and calculates the Authenticode-specific image digest rather than hashing the entire file blindly. The PE checksum field and the security-directory/certificate area are treated specially according to the Authenticode layout.

This digest is compared by `authenticode_verifier` with the digest carried inside `SpcIndirectDataContent`.

## PE checksum

The plugin also provides:

- `read_checksum()`
- `calc_checksum()`
- `update_checksum()`

These operate on the PE `CheckSum` field independently of the Authenticode cryptographic digest.

## Plugin boundary

`authenticode_plugin` defines the generic engine interface. The verifier therefore does not need to know PE parsing details directly:

```text
verifier
  ↓
authenticode_plugin
  ↓
authenticode_plugin_pe
  ├─ detect PE
  ├─ extract signature
  ├─ calculate Authenticode digest
  └─ PE checksum
```

The current PE plugin reports itself as a non-separated engine; the separated-file hooks remain part of the plugin interface but are not implemented for this PE plugin.

## Related source

- `sdk/crypto/authenticode/authenticode_plugin.hpp`
- `sdk/crypto/authenticode/authenticode_plugin.cpp`
- `sdk/crypto/authenticode/authenticode_plugin_pe.hpp`
- `sdk/crypto/authenticode/authenticode_plugin_pe.cpp`

## Related test / sample

- `test/applet/authenticode/sample.cpp`

The applet demonstrates verification against a supplied executable and trust certificate; the PE plugin itself does not have a separate testcase directory.
