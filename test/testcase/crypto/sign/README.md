## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Digital signatures and MAC Testcases

## 1. Role

This directory contains test sources for digital signatures and mac in hotplace. The category covers signature creation/verification, ECDSA, RSA signatures, HMAC, X.509 handling, ML-DSA, and SLH-DSA.

## 2. Test model

### Signature and MAC testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_crypto_sign.cpp`
* `testcase_ecdsa.cpp`
* `testcase_hmac.cpp`
* `testcase_mldsa.cpp`
* `testcase_rsassa.cpp`
* `testcase_slhdsa.cpp`
* `testcase_x509.cpp`
* `testvector_dsa.cpp`
* `testvector_ecdsa.cpp`
* `testvector_rsassa.cpp`

#### test data / build files

* `testvector_dsa.yml`
* `testvector_ecdsa.yml`
* `testvector_rsassa.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

Source files in this directory: `testcase_crypto_sign.cpp`, `testcase_ecdsa.cpp`, `testcase_hmac.cpp`, `testcase_mldsa.cpp`, `testcase_rsassa.cpp`, `testcase_slhdsa.cpp`, `testcase_x509.cpp`, `testvector_dsa.cpp`, `testvector_ecdsa.cpp`, `testvector_rsassa.cpp`

## 3. Example: Digital signatures and MAC source example

`testcase_crypto_sign.cpp` records sign and verify outcomes, checks selected signature lengths, and includes negative-path expectations. Separate vector sources target DSA, ECDSA, and RSA signature examples.

## 4. Test and verification status

### 4.1 Source-level coverage

The source contains positive and negative outcome checks plus selected signature-size assertions. The report includes `expt` and `skip` classifications; those are kept separate from pass counts and not reinterpreted here.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Implementation notes: `sdk/crypto/basic/sign.md`, `sdk/crypto/basic/mac.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 6. References

Source files in this directory:
- `test/testcase/crypto/sign/testcase_crypto_sign.cpp`
- `test/testcase/crypto/sign/testcase_ecdsa.cpp`
- `test/testcase/crypto/sign/testcase_hmac.cpp`
- `test/testcase/crypto/sign/testcase_mldsa.cpp`
- `test/testcase/crypto/sign/testcase_rsassa.cpp`
- `test/testcase/crypto/sign/testcase_slhdsa.cpp`
- `test/testcase/crypto/sign/testcase_x509.cpp`
- `test/testcase/crypto/sign/testvector_dsa.cpp`
- `test/testcase/crypto/sign/testvector_ecdsa.cpp`
- `test/testcase/crypto/sign/testvector_rsassa.cpp`
