# Windows Authenticode Verification

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`sdk/crypto/authenticode` implements the project's Windows Authenticode verification path. The scope is deliberately narrow: inspect a signed PE file, extract its Authenticode/PKCS#7 data, verify the embedded digest and certificate/signature information, and perform the PE-specific checks needed by the verifier.

This is **not** a general-purpose digital-certificate or PKI framework.

## Implementation map

| Module | Role |
|---|---|
| `authenticode_verifier` | verification context, engine selection, PE signature/digest verification, certificate trust handling |
| `authenticode_plugin` | format-independent plugin interface |
| `authenticode_plugin_pe` | PE detection, Authenticode extraction, PE image digest and checksum handling |
| `sdk.cpp` | Authenticode-specific PKCS#7/ASN.1 helper structures and CRL/X.509 helpers |

## Documents

- [authenticode-verifier](authenticode_verifier.md)
- [authenticode-pe-plugin](authenticode-pe-plugin.md)

## Verification flow

```text
PE file
  ↓
authenticode_plugin_pe::is_kind_of()
  ↓
authenticode_plugin_pe::extract()
  ↓
PKCS#7 / SpcIndirectDataContent
  ↓
pkcs7_digest_info()
  ↓
PE Authenticode image digest
  ↓
digest comparison
  ↓
certificate / signer verification
```

The public entry point is `authenticode_verifier::verify()`.

## Related areas

- `sdk/crypto/basic/openssl_sdk.hpp` — OpenSSL startup/hash support
- `sdk/crypto/` — cryptographic primitives and certificate-related facilities used by verification
- `sdk/io/stream/` — PE file access through `file_stream`
- `sdk/io/string/` — CRL URL decomposition through `split_url`
- `sdk/io/asn.1/` — ASN.1 concepts relevant to the wider project; this verifier uses OpenSSL's PKCS#7/X.509 APIs directly for this path

## Test / applet

There is no dedicated `test/testcase/crypto/authenticode/` directory. The practical executable is:

- `test/applet/authenticode/sample.cpp`

The applet opens a target file, adds a trust certificate (`trust.crt`), disables CRL download for the sample, and invokes `verify()` with the separated-signature flag enabled.

## Historical scope

The verifier source records a long evolution from Windows SDK based verification, through an OpenSSL implementation, to the current plugin-oriented PE implementation. MSI/Cabinet engines are explicitly outside the current PE-focused implementation.
