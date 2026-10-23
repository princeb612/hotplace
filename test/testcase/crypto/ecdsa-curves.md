## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Ecdsa Curves

## 1. Role

This document records testcase organization, test-vector schema, or reference material for the crypto test area. Its presence does not by itself establish runtime verification.

## 2. Test model

#### ECDSA signature/hash algorithm

| hash   | sizeof R+S |
|   --   |     --     |
| sha1   | 40         |
| sha224 | 56         |
| sha256 | 64         |
| sha384 | 96         |
| sha512 | 132        |


- sha1 | sha2_224 | sha2_256 | sha2_384 | sha2_512
1.   - NID_secp112r1 : secp112r1, wap-wsg-idm-ecid-wtls6
  - NID_secp112r2 : secp112r2
  - NID_secp128r1 : secp128r1
  - NID_secp128r2 : secp128r2
  - NID_secp160k1 : ansip160k1, secp160k1
  - NID_secp160r1 : ansip160r1, secp160r1, wap-wsg-idm-ecid-wtls7
  - NID_secp160r2 : ansip160r2, secp160r2
  - NID_sect113r2 : sect113r2
  - NID_sect131r1 : sect131r1
  - NID_sect131r2 : sect131r2
  - NID_brainpoolP160r1 : brainpoolP160r1
  - NID_brainpoolP160t1 : brainpoolP160t1
- sha2_224 | sha2_256 | sha2_384 | sha2_512
2.   - NID_secp192k1 : ansip192k1, secp192k1
  - NID_X9_62_prime192v1 : P-192, prime192v1, secp192r1
  - NID_secp224k1 : ansip224k1, secp224k1
  - NID_secp224r1 : P-224, ansip224r1, secp224r1, wap-wsg-idm-ecid-wtls12
  - NID_sect163k1 : K-163, ansit163k1, sect163k1, wap-wsg-idm-ecid-wtls3
  - NID_sect163r1 : ansit163r1, sect163r1
  - NID_sect163r2 : B-163, ansit163r2, sect163r2
  - NID_sect193r1 : ansit193r1, sect193r1
  - NID_sect193r2 : sect193r2
  - NID_brainpoolP192r1 : brainpoolP192r1
  - NID_brainpoolP192t1 : brainpoolP192t1
  - NID_brainpoolP224r1 : brainpoolP224r1
  - NID_brainpoolP224t1 : brainpoolP224t1
- sha2_256 | sha2_384 | sha2_512
3.   - NID_secp256k1 : ansip256k1, secp256k1
  - NID_X9_62_prime256v1 : P-256, prime256v1, secp256r1
  - NID_sect233k1 : K-233, ansit233k1, sect233k1, wap-wsg-idm-ecid-wtls10
  - NID_sect233r1 : B-233, ansit233r1, sect233r1, wap-wsg-idm-ecid-wtls11
  - NID_sect239k1 : ansit239k1, sect239k1
  - NID_brainpoolP256r1 : brainpoolP256r1
  - NID_brainpoolP256t1 : brainpoolP256t1
- sha2_384 | sha2_512
4.   - NID_secp384r1 : P-384, ansip384r1, secp384r1
  - NID_sect283k1 : K-283, ansit283k1, sect283k1
  - NID_sect283r1 : B-283, ansit283r1, sect283r1
  - NID_brainpoolP320r1 : brainpoolP320r1
  - NID_brainpoolP320t1 : brainpoolP320t1
  - NID_brainpoolP384r1 : brainpoolP384r1
  - NID_brainpoolP384t1 : brainpoolP384t1
- sha2_512
5.   - NID_secp521r1 : P-521, ansip521r1, secp521r1
  - NID_secp521r1 : sect113r1, wap-wsg-idm-ecid-wtls4
  - NID_sect409k1 : K-409, ansit409k1, sect409k1
  - NID_sect409r1 : B-409, ansit409r1, sect409r1
  - NID_brainpoolP512r1 : brainpoolP512r1
  - NID_brainpoolP512t1
- N/A
6.   - NID_sect571k1 : K-571, ansit571k1, sect571k1
  - NID_sect571r1 : B-571, ansit571r1, sect571r1

## 3. Example: Source inventory and test-vector use

1. The retained material is a schema/reference or directory-level record. Consult the listed testcase source files to determine which functions consume these inputs and what assertions they make.

## 4. Test and verification status

### 4.1 Source-level coverage

No claim of algorithmic coverage is inferred from this reference document alone. Coverage must be established from the consuming C++ testcase functions and their expected-result checks.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Crypto implementation: `sdk/crypto/README.md`
- Test sources and vector consumers are located in the corresponding sibling testcase directories.
- Related testcase source: `test/testcase/crypto/sample.cpp`



## 6. References

No external references are currently listed.
