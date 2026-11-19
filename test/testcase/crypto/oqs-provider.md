## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Oqs Provider

## 1. Role

This document records testcase organization, test-vector schema, or reference material for the crypto test area. Its presence does not by itself establish runtime verification.

## 2. Test model

#### oqs-provider

* [oqs-provider](https://github.com/open-quantum-safe/oqs-provider/)
- [ ] study
1.   - [x] encode/decode
    - [x] DER, PEM
    - [x] public, private, encrypted private
  - [x] KEM
    - [x] build OQS_KEM_ENCODERS
    - [x] encapsulate/decapsulate
  - [x] DSA
    - [x] sign/verify
  - [ ] test vector
    - [ ] [ML-DSA-keyGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204)
    - [ ] [ML-DSA-sigGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204)
    - [ ] [ML-DSA-sigVer-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)
    - [ ] [ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)
    - [ ] [ML-KEM-encapDecap-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)

## 3. Example: Source inventory and test-vector use

1. The retained material is a schema/reference or directory-level record. Consult the listed testcase source files to determine which functions consume these inputs and what assertions they make.

## 4. Test and verification status

### 4.1 Source-level coverage

No claim of algorithmic coverage is inferred from this reference document alone. Coverage must be established from the consuming C++ testcase functions and their expected-result checks.

### 4.2 Documentation and verification status

The referenced `test/testcase/crypto/report` file is not present in the current branch, so these historical totals cannot be verified from the checked-in source tree and are not asserted here. No tests were executed during this documentation pass. The source-basis marker records the revision used to verify the current test-source mapping; it does not update the older checklist state above.

## 5. Relationships

- Crypto implementation: [`sdk/crypto/README.md`](../../../sdk/crypto/README.md)
- Provider adapter: [`sdk/crypto/oqs/README.md`](../../../sdk/crypto/oqs/README.md)
- Common and provider-backed testcase map: [`pqc/README.md`](pqc/README.md)
- Build-time source selection and testcase dispatch: `CMakeLists.txt`, `sample.cpp`
- Provider-backed sources: `pqc/oqs/testcase_oqs_encode.cpp`, `pqc/oqs/testcase_oqs_kem.cpp`, `pqc/oqs/testcase_oqs_dsa.cpp`



## 6. References

No external references are currently listed.
