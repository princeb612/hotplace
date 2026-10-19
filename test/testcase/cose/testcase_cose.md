## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# COSE testcase analysis

## 1. Role

Records source-level evidence for COSE message parsing/composition, cryptographic processing, resource metadata, and RFC test vectors.

## 2. Test model

```text
RFC / COSE example assets
          │
          ▼
 CBOR parse and message/layer model
          │
          ├── compose / serialize comparisons
          └── sign / verify / encrypt / decrypt / MAC paths
                         │
                         ▼
                  test_case result
```

The main sources include `testcase_cose.cpp`, `testcase_rfc8152.cpp`, `testcase_rfc8392.cpp`, `testcase_resource.cpp`, `testcase_akp.cpp`, and `testvector_cose_examples.cpp`. Assets include paired `.cbor` and `.diag` files and YAML/JSON test vectors.

## 3. Example: RFC vectors and cryptographic processing

`testcase_rfc8152.cpp` contains byte comparisons for CBOR composition/parsing and uses RFC example cases for verification/decryption paths. `testcase_cose.cpp` has explicit sign/verify, encrypt/decrypt, and MAC/verify calls. `testcase_resource.cpp` checks selected algorithm/resource metadata. `testcase_akp.cpp` exercises asymmetric-key-package signing/verification paths when supported; its source also records a not-supported result for the OpenSSL 3.5 requirement.

## 4. Test and verification status

### 4.1 Source-level coverage

- RFC vector cases compare composed or parsed CBOR bytes against expected data.
- Cryptographic test paths call sign/verify, encrypt/decrypt, and MAC/verify operations.
- Resource tests compare selected metadata fields with expected values.
- AKP tests include a runtime capability gate; the source path does not imply support in every OpenSSL build.
- The supplied vectors exercise specific cases and do not establish exhaustive algorithm or malformed-input coverage.

### 4.2 Documentation and verification status

The supplied report is identified as **MinGW64, source revision 1104**: **2013 pass, 0 expt, 0 fail, 2 skip, 0 triv**. The two skips remain skips; they are not counted as passes. This documentation task did not rerun the tests.

## 5. Relationships

- `sdk/crypto/cose/` — COSE message model, composer, recipients, keys, countersignatures, and crypto processing.
- `sdk/io/cbor/` — CBOR representation and serialization.
- `sdk/crypto/basic/` — keys, signatures, MAC, AEAD, and KDF implementations.
- `test/testcase/cose/` — RFC vectors, diagnostic examples, COSE YAML examples, and AKP JSON vectors.

## 6. References

- RFC 8152 / RFC 9052 — COSE message definitions.
- RFC 8392 — CBOR Web Token.
- RFC 8778 — HSS/LMS with COSE.
- RFC 9338 — COSE Countersignatures.
- `test/testcase/cose/` source and vector files (Revision 1104).
