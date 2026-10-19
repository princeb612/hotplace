## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Randomness, nonces and tokens Testcases

## 1. Role

This directory contains test sources for randomness, nonces and tokens in hotplace. The category covers random bytes, nonce generation, and token generation.

## 2. Test model

### Random-number generation testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_random.cpp`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

Source files in this directory: `testcase_random.cpp`

## 3. Example: Randomness, nonces and tokens source example

`testcase_random.cpp` defines `test_random()`, `test_nonce()`, and `test_token()` and records the operation result after repeated generation loops.

## 4. Test and verification status

### 4.1 Source-level coverage

The inspected source checks operation results for random, nonce, and token loops. Such tests do not by themselves establish statistical quality, entropy-source properties, or cryptographic suitability.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Implementation notes: `sdk/crypto/basic/backend.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 6. References

Source files in this directory:
- `test/testcase/crypto/prng/testcase_random.cpp`
