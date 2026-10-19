## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Keys and key exchange Testcases

## 1. Role

This directory contains test sources for keys and key exchange in hotplace. The category covers key import/export, key generation, DER/JWK/CWK representations, curves, DH/EC, HPKE, and key-share/vector paths.

## 2. Test model

### Key and key-exchange testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_crypto_key.cpp`
* `testcase_curves.cpp`
* `testcase_der.cpp`
* `testcase_dh.cpp`
* `testcase_ec.cpp`
* `testcase_hpke.cpp`
* `testcase_key_dsa.cpp`
* `testcase_key_ffdhe.cpp`
* `testcase_key_mlkem.cpp`
* `testcase_key_rsa.cpp`
* `testcase_keyexchange.cpp`
* `testcase_keygen.cpp`
* `testvector_keygen.cpp`
* `testvector_keyshare.cpp`
* `testvector_rfc7919.cpp`

#### test data / build files

* `testvector_keygen.yml`
* `testvector_keyshare.yml`
* `testvector_rfc7919.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

Source files in this directory: `testcase_crypto_key.cpp`, `testcase_curves.cpp`, `testcase_der.cpp`, `testcase_dh.cpp`, `testcase_ec.cpp`, `testcase_hpke.cpp`, `testcase_key_dsa.cpp`, `testcase_key_ffdhe.cpp`, `testcase_key_mlkem.cpp`, `testcase_key_rsa.cpp`, `testcase_keyexchange.cpp`, `testcase_keygen.cpp`, `testvector_keygen.cpp`, `testvector_keyshare.cpp`, `testvector_rfc7919.cpp`

## 3. Example: Keys and key exchange source example

`testcase_crypto_key.cpp` includes an explicit leading-zero key-size check and records JWK/CWK results. Other files cover RSA/DSA keys, EC/DH, FFDHE, ML-KEM, HPKE, DER, key generation, and key-share vectors.

## 4. Test and verification status

### 4.1 Source-level coverage

The inspected key source includes concrete assertions for preserving leading zeroes and result checks for selected key formats. Not-supported outcomes are represented explicitly and should not be counted as algorithm-success coverage.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Implementation notes: `sdk/crypto/basic/key.md`, `sdk/crypto/basic/elliptic-curves.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 6. References

Source files in this directory:
- `test/testcase/crypto/key/testcase_crypto_key.cpp`
- `test/testcase/crypto/key/testcase_curves.cpp`
- `test/testcase/crypto/key/testcase_der.cpp`
- `test/testcase/crypto/key/testcase_dh.cpp`
- `test/testcase/crypto/key/testcase_ec.cpp`
- `test/testcase/crypto/key/testcase_hpke.cpp`
- `test/testcase/crypto/key/testcase_key_dsa.cpp`
- `test/testcase/crypto/key/testcase_key_ffdhe.cpp`
- `test/testcase/crypto/key/testcase_key_mlkem.cpp`
- `test/testcase/crypto/key/testcase_key_rsa.cpp`
- `test/testcase/crypto/key/testcase_keyexchange.cpp`
- `test/testcase/crypto/key/testcase_keygen.cpp`
- `test/testcase/crypto/key/testvector_keygen.cpp`
- `test/testcase/crypto/key/testvector_keyshare.cpp`
- `test/testcase/crypto/key/testvector_rfc7919.cpp`
