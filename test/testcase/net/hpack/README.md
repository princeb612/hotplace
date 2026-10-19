## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HPACK testcases

## 1. Role

This directory contains HPACK testcase sources for RFC 7541 examples, Huffman coding, and YAML test vectors.

## 2. Test model

Test source files in this directory: `test.cpp`, `testcase_huffman.cpp`, `testcase_rfc7541.cpp`, `testvector_hpack.cpp`

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `test.cpp`
* `testcase_huffman.cpp`
* `testcase_rfc7541.cpp`
* `testvector_hpack.cpp`

#### test data / build files

* `testvector_hpack.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.

## 3. Example: testcase entry points

The concrete test entry points and test-vector schema are retained below. Source-level assertions, rather than the existence of a source file, determine what is actually checked.

Source files:
- `test.cpp`
- `testcase_huffman.cpp`
- `testcase_rfc7541.cpp`
- `testvector_hpack.cpp`

## 4. Test and verification status

### 4.1 Source-level coverage

Coverage must be inferred from the actual testcase functions and assertions. The directory README and the presence of test sources do not prove that every protocol path is meaningfully checked.

### 4.2 Documentation and verification status

This README documents the directory and source inventory. It does not itself prove a successful runtime execution. The available report archive does not identify the exact OS, compiler configuration, or source revision for its results.

## 5. Relationships

- Corresponding implementation documentation is under `sdk/net/`.
- HTTP compression testcases are maintained in the sibling `hpack/` and `qpack/` directories.
- Shared test registration is defined by the surrounding testcase CMake configuration.

## 6. References

- `test/testcase/net/hpack/test.cpp`
- `test/testcase/net/hpack/testcase_huffman.cpp`
- `test/testcase/net/hpack/testcase_rfc7541.cpp`
- `test/testcase/net/hpack/testvector_hpack.cpp`
