# Authenticode Verifier

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`authenticode_verifier` is the orchestration layer for Authenticode verification.

## Context

`authenticode_context_t` holds:

- registered verification engines
- trusted signer/certificate information
- CRL/cache state and related paths/options
- proxy and certificate/CRL configuration
- synchronization for shared verification state

The normal lifecycle is:

```text
authenticode_verifier
  → open(context)
  → configure trust/options
  → verify(context, file, flags, result)
  → close(context)
```

OpenSSL startup/cleanup is owned by the verifier object in the current implementation.

## Main verification path

`verify()` opens the file with `file_stream`, selects an engine by calling `is_kind_of()`, and asks the matched engine to extract the Authenticode binary.

For the PE engine this gives the PKCS#7 signature data. The verifier then:

1. decodes the data with OpenSSL `d2i_PKCS7_bio()`;
2. reads the Authenticode `SpcIndirectDataContent` digest algorithm and expected digest;
3. asks the selected engine to calculate the file's Authenticode image digest;
4. compares the embedded digest with the calculated digest;
5. verifies the PKCS#7/certificate side of the signature.

A digest mismatch is returned as `digest_failure` before certificate verification is accepted.

## PE-specific boundary

The verifier does not treat the entire PE file as a normal file digest. The PE plugin supplies the Authenticode image-digest calculation and extraction boundary:

```text
PE image
   │
   ├── PE headers / checksum exclusions
   ├── certificate table exclusion
   └── Authenticode hashing rules
            │
            ▼
     calculated image digest
            │
            ├── compare with SpcIndirectDataContent digest
            │
            └── continue to signer/certificate verification
```

This is why `authenticode_plugin_pe` is separate from the generic verifier orchestration: PE layout rules belong to the format plugin, while trust/signature orchestration belongs to `authenticode_verifier`.

## Trust handling

The context can register trusted signers and trusted root certificates. During PKCS#7 verification the implementation builds an OpenSSL `X509_STORE`, loads the configured trust material, and performs certificate-chain/signature checks.

The verifier also inspects CRL distribution points. CRL download/cache handling exists in the code and is configurable, but the source comments mark this area as temporary/under construction; the applet explicitly disables CRL download for its sample verification path.

## URL interaction

CRL distribution points may contain URLs. The verifier uses `sdk/io/string::split_url()` when mapping CRL URLs to its configured local CRL path/cache representation.

This is one of the concrete consumers of the `sdk/io/string` URL module.

## Scope

The verifier is not a generic certificate-validation framework. Its surrounding state and helper functions exist to support the Authenticode verification flow, especially PKCS#7 signed data, signer trust, PE digest checking and PE-specific metadata.

## Related source

- `sdk/crypto/authenticode/authenticode_verifier.hpp`
- `sdk/crypto/authenticode/authenticode_verifier.cpp`
- `sdk/crypto/authenticode/sdk.cpp`
- `sdk/crypto/authenticode/sdk.hpp`

## Test / sample

- `test/applet/authenticode/sample.cpp`
