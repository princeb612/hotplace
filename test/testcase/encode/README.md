## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: encoding testcase inventory
```

# Encoding testcases

## 1. Role

This directory contains testcases for the encoding module: Base128, Base16, Base64 and Huffman coding. The testcase sources define the tested inputs and expected outputs; this directory overview does not itself establish runtime success.

## 2. Test model

- `sample.cpp` — testcase entry point.
- `testcase_base128.cpp` — Base128 encoding/decoding behavior.
- `testcase_base16.cpp` — hexadecimal conversion.
- `testcase_base64.cpp` — Base64 conversion.
- `testcase_huffman.cpp` — Huffman coding behavior.

## 3. Example: encoding round trip

For each encoding family, follow the testcase from input bytes/text through the encoder, then the decoder and the expected-result assertion. Keep valid-input round trips separate from fixed known-answer vectors and malformed-input checks; they establish different properties.

## 4. Test and verification status

### 4.1 Source-level coverage

The source inventory identifies the encoding families represented by the testcase sources. Exact boundary/error coverage must be inferred from each function's assertions.

### 4.2 Documentation and verification status

The latest available aggregate report is indexed in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 215 pass, 0 expt, 0 fail, 0 skip and 0 triv entries for the `encode` group. The report files do not independently identify the tested source commit or exact build configuration. This documentation update did not execute the tests; preserve the snapshot until a newer, revision-associated report is supplied.

## 5. Relationships

- `sdk/base/encoding/` — base encoding primitives.
- `test/testcase/CMakeLists.txt` and this directory's `CMakeLists.txt` — target registration.
- `test/testcase/base/` — related low-level binary/value utilities.

## 6. References

- `sample.cpp`
- `testcase_base128.cpp`
- `testcase_base16.cpp`
- `testcase_base64.cpp`
- `testcase_huffman.cpp`
- `CMakeLists.txt`
