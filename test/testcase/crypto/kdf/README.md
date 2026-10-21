## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Key derivation functions Testcases

## 1. Role

This directory contains test sources for key derivation functions in hotplace. The category covers HKDF and RFC-based KDF vectors including PBKDF2, scrypt, Argon2, and CMAC-based derivation cases.

## 2. Test model

### KDF testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_hkdf.cpp`
* `testcase_rfc6070.cpp`
* `testcase_rfc7914.cpp`
* `testcase_rfc9106.cpp`
* `testvector_rfc4615.cpp`
* `testvector_rfc5869.cpp`

#### test data / build files

* `testvector_rfc4615.yml`
* `testvector_rfc5869.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

Source files in this directory: `testcase_hkdf.cpp`, `testcase_rfc6070.cpp`, `testcase_rfc7914.cpp`, `testcase_rfc9106.cpp`, `testvector_rfc4615.cpp`, `testvector_rfc5869.cpp`

## 3. Example: Key derivation functions source example

`testcase_hkdf.cpp` compares the decoded expected vector with the derived result. Additional files target RFC 6070, RFC 7914, RFC 9106, RFC 4615, and RFC 5869.

## 4. Test and verification status

### 4.1 Source-level coverage

HKDF includes an explicit expected-result comparison. Other test files and YAML vectors are tied to named RFC cases; their presence is not itself proof that all inputs passed.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Implementation notes: `sdk/crypto/basic/kdf/README.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 6. References

Source files in this directory:
- `test/testcase/crypto/kdf/testcase_hkdf.cpp`
- `test/testcase/crypto/kdf/testcase_rfc6070.cpp`
- `test/testcase/crypto/kdf/testcase_rfc7914.cpp`
- `test/testcase/crypto/kdf/testcase_rfc9106.cpp`
- `test/testcase/crypto/kdf/testvector_rfc4615.cpp`
- `test/testcase/crypto/kdf/testvector_rfc5869.cpp`
