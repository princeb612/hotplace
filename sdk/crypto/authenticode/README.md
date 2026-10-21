# Windows Authenticode Verification

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

## 1. Role

`sdk/crypto/authenticode/` implements the project's Authenticode verification path for Windows Portable Executable (PE) files. It extracts the embedded signature material, calculates the PE Authenticode image digest, compares it with the digest described by the signed content, and delegates signer/certificate verification to OpenSSL.

This module is a format-specific verification feature, **not a general-purpose PKI framework**. The current concrete format implementation is PE; the abstract plugin interface still carries hooks associated with separated signatures and other historical file formats.

## 2. Data Model

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

## 3. Behavior Model

- The PE image digest is **not** an ordinary hash of every file byte. PE checksum and certificate-table regions are handled according to the Authenticode hashing layout.
- `authenticode_plugin_pe` owns PE layout knowledge; `authenticode_verifier` owns orchestration and trust configuration.
- `authenticode_context_t` is opened through `authenticode_verifier::open()`, configured, passed to `verify()`, and released with `close()`. Trust roots can be added with `add_trusted_rootcert()`.
- The PE plugin reports `separated() == false`; the interface's separated-file hooks should not be read as proof that this PE implementation verifies detached signatures.
- The verifier uses OpenSSL PKCS#7/X.509 APIs directly. The wider project's ASN.1 runtime is not a direct dependency of this verification path.

### 3.1 Current signing-time exception and CRL path

This subsection records the implementation visible in Revision 1105. It is a source-level behavior map, not a statement that the code implements every Authenticode or PKI validation requirement.

```text
authenticode_verifier::verify()
  │
  ├─ extract PE Authenticode payload
  ├─ decode PKCS#7 SignedData
  ├─ compare SpcIndirectDataContent digest with PE image digest
  │
  ▼
verify_pkcs7()
  │
  ├─ enumerate signer certificates and certificates embedded in PKCS#7
  │    └─ get_crl(cert)
  │         ├─ read CRL distribution-point URI(s) from certificate
  │         ├─ derive local cache/file path from each URI
  │         ├─ reuse context->crl_map entry if already cached
  │         ├─ otherwise read local CRL file
  │         └─ if absent, optionally invoke wget via process
  │              └─ decode downloaded file as X509_CRL
  │
  ├─ create X509_STORE and load default paths + configured trusted certificate files
  ├─ install verify_callback()
  ├─ set X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL
  ├─ add successfully decoded CRLs to X509_STORE
  │
  ▼
PKCS7_verify()
  │
  ├─ chain/certificate validation callback
  │    └─ if current error is CERT_HAS_EXPIRED and depth == 0:
  │         └─ is_valid_by_timestamp(current_cert, pkcs7)
  │              ├─ find PKCS#7 signer-info counterSignature attribute
  │              ├─ decode its inner SignerInfo
  │              ├─ read its signed signingTime attribute
  │              └─ compare signingTime with certificate notBefore/notAfter
  │                   ├─ within interval -> clear CERT_HAS_EXPIRED and accept callback
  │                   └─ absent/outside interval -> do not apply exception
  │
  └─ verification result -> success / verification_failure
```

#### What the current code does

1. **Timestamp extraction is narrow.** `extract_timestamp_time_from_signer_info()` looks for the PKCS#7 `counterSignature` attribute on a signer-info and reads the inner signer-info's signed `signingTime`. The current path does not establish, by this helper alone, that a trusted timestamp authority's certificate chain and timestamp-token signature have been validated.
2. **The exception only addresses signer-certificate expiry.** `verify_callback()` applies `is_valid_by_timestamp()` only for `X509_V_ERR_CERT_HAS_EXPIRED` at depth zero. It compares the extracted time against the current certificate's `notBefore` and `notAfter`. It does not apply this exception to every certificate in the chain or to every certificate-time error.
3. **The timestamp check is not a general historical validation mode.** The shown code does not configure OpenSSL to validate the entire chain at the timestamp. It handles the specific expired-signer-certificate callback case with a separate comparison.
4. **CRL retrieval and CRL policy are separate from the expiry exception.** `get_crl()` collects CRL distribution-point URIs and attempts local-file/cache lookup, with an optional external `wget` process when downloading is enabled. Successfully decoded CRLs are added to the store; `CRL_CHECK` and `CRL_CHECK_ALL` are set before `PKCS7_verify()`.
5. **Retrieval is not proof of successful revocation checking.** The sample enables downloading through `authenticode_ctrl_t::set_crl = 1`; it can be disabled for an air-gapped environment. If a needed CRL cannot be obtained or decoded, the code does not synthesize a valid CRL. The callback's `X509_V_ERR_UNABLE_TO_GET_CRL` case does not clear that error or force success, so the overall verification can still fail.
6. **The code path should not be described as “timestamp makes the certificate valid.”** It is more precise to say that a specific expired-certificate error at signer depth zero may be overridden when the extracted counter-signing time falls inside that certificate's validity interval. CRL checks remain separately enabled and can still affect the result.

#### Review points to revisit when the implementation changes

- Is the counter-signature `signingTime` the intended source of signing time, or should the implementation validate a standards-compliant Authenticode/RFC 3161 timestamp token and its TSA chain?
- Is the timestamp signature and its trust chain verified before its time is used as evidence?
- Should historical-time validation apply to the whole signer chain, and how should certificate validity and revocation status be evaluated at the relevant time?
- Are CRLs validated for issuer/signature, freshness (`thisUpdate`/`nextUpdate`), scope, and relevant certificate serial number as expected from OpenSSL's configured store checks?
- What is the intended behavior when a CRL URI is missing, unreachable, cached but stale, malformed, or yields no CRL? Should this fail closed, and how should the outcome be surfaced?
- Does the local cache need freshness/revalidation rules? The current context-level map reuses entries for the lifetime of the verifier context.
- Are tests needed for: expired signer with/without counter-signature time; time before `notBefore`, within the interval, and after `notAfter`; absent/unreachable/malformed/expired CRL; revoked versus non-revoked signer; and chain certificates at nonzero depth?

These are explicit review questions, not claims that each behavior is currently implemented or tested.

## 4. Relationships

- [`authenticode_verifier.md`](authenticode_verifier.md) — context lifecycle, verification stages, trust and CRL boundaries.
- [`authenticode-pe-plugin.md`](authenticode-pe-plugin.md) — PE parsing, digest exclusions and checksum API.
- [`../../basic/openssl_sdk.hpp`](../basic/openssl_sdk.hpp) — OpenSSL initialization/hash support used by the surrounding crypto layer.
- [`../../../io/stream/`](../../io/stream/) — file access through `file_stream`.
- [`../../../io/string/`](../../io/string/) — CRL URL decomposition through `split_url`.
- [`../../base/system/`](../../base/system/) — process execution used by the CRL retrieval path.
- [`../../io/asn.1/`](../../io/asn.1/) — broader ASN.1 module; not the direct parser used for this PKCS#7 path.
- [`../../../test/applet/authenticode/`](../../../test/applet/authenticode/) — sample executable and build definition.

### Implementation and source entry points

- `authenticode.hpp`, `authenticode_verifier.hpp/.cpp`, `authenticode_plugin.hpp/.cpp`, `authenticode_plugin_pe.hpp/.cpp`, `sdk.hpp/.cpp`, `types.hpp`.
- `test/applet/authenticode/README.md`, `sample.cpp`, `CMakeLists.txt`.

### Development Notes (for maintainer review)

- Source comments and revision history record the evolution from Windows SDK verification to OpenSSL and then to a plugin-oriented implementation. Keep this history distinct from the current supported-format claim.
- The plugin interface documents PE, MSI, and Cabinet as historical/intended engine types, but this directory's concrete implementation and this documentation scope are PE-focused.
- Although older source comments describe CRL retrieval as temporary or under construction, the current implementation includes an external-process download path and CRL-check flags. Treat this as an implemented mechanism, not proof of a complete production revocation policy. The sample currently enables CRL retrieval and comments that it can be disabled for an air-gapped network; actual outcomes still depend on certificate distribution-point data, network/process configuration, cache state, and trust-store settings.

### Test evidence and source entry points

`test/applet/authenticode/sample.cpp` demonstrates the concrete calling sequence: open a verifier context, set `authenticode_ctrl_t::set_crl` to `1` (with a source comment noting that it may be set to `0` for an air-gapped network), add `trust.crt` as trusted root material, call `verify()`, close the context, and report the result. It is an applet/sample rather than a dedicated `test/testcase/crypto/authenticode/` testcase directory.

A typical invocation shown in the source comments is `test-authenticate -v -i /path/to/target.exe`; the target file and `trust.crt` must be supplied in the environment. This documentation pass did not run the applet.
