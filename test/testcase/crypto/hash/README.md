## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Hash, HMAC and transcript hash Testcases

## 1. Role

This directory contains test sources for hash, hmac and transcript hash in hotplace. The category covers digest algorithms, keyed hashes, OTP-related RFC examples, and transcript-hash support.

## 2. Test model

### Hash, HMAC and transcript-hash testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_openssl_hash.cpp`
* `testcase_rfc4226.cpp`
* `testcase_rfc4231.cpp`
* `testcase_rfc4493.cpp`
* `testcase_rfc6238.cpp`
* `testcase_transcript_hash.cpp`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

Source files in this directory: `testcase_openssl_hash.cpp`, `testcase_rfc4226.cpp`, `testcase_rfc4231.cpp`, `testcase_rfc4493.cpp`, `testcase_rfc6238.cpp`, `testcase_transcript_hash.cpp`

## 3. Example: Hash, HMAC and transcript hash source example

`testcase_openssl_hash.cpp` routes digest/HMAC operations through `test_hash_routine()` and records result codes. Separate sources cover RFC 4226, RFC 4231, RFC 4493, RFC 6238, and transcript hashing.

## 4. Test and verification status

### 4.1 Source-level coverage

The OpenSSL hash source exercises multiple algorithms and records result outcomes; the RFC-specific files target named standards. Coverage is not an exhaustive security assessment of all algorithms or provider versions.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Implementation notes: `sdk/crypto/basic/digest/README.md`, `sdk/crypto/basic/mac/README.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 6. References

Source files in this directory:
- `test/testcase/crypto/hash/testcase_openssl_hash.cpp`
- `test/testcase/crypto/hash/testcase_rfc4226.cpp`
- `test/testcase/crypto/hash/testcase_rfc4231.cpp`
- `test/testcase/crypto/hash/testcase_rfc4493.cpp`
- `test/testcase/crypto/hash/testcase_rfc6238.cpp`
- `test/testcase/crypto/hash/testcase_transcript_hash.cpp`
