## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parser and Lexer Testcases

## 1. Role

Documents the parser/lexer test sources and test vectors under `test/testcase/io/parser`.

## 2. Test model

The directory contains parser and lexer C++ test sources, YAML parser test vectors, and ASN.1 sample modules. The source-level test functions include parser, lexer, parsing-table loading, YAML test-vector parsing, and ASN.1 notation/parameterized paths.

## 3. Example: follow the assertions

- `testcase_lexer.cpp::test_lexer()` compares token counts for a base lexer configuration and an ASN.1-configured lexer; `test_lexer_hexstring()` compares the exact token-ID sequence for an ASN.1-style hex-string example.
- `testcase_parser.cpp::test_asn1_notation()` checks that four parser instances (LALR build/import and GLR build/import) are ready, then runs a shared set of notation vectors through each. `test_load_parsingtable()` isolates the binary table import path.
- `testvector_parser.cpp::test_yaml_testvector_parser()` reads `testvector_parser.yml`, compares reducer-produced module clause ranges with expected ranges, and verifies level-trigger and edge-trigger behavior.

The first two are lexer/parser tests; the YAML test is a context-aware module-boundary pre-parser. Keep their purposes distinct when interpreting a pass or failure.

## 4. Test and verification status

### 4.1 Source-level coverage

This document inventories test entry points but does not claim all parser grammar cases are covered. For a specific production, review its input vector and expected parse result alongside the actual assertion.

### 4.2 Documentation and verification status

The source assertions described here are source-level evidence, not a new runtime run. The supplied report archive does not record the exact OS/compiler configuration or source revision; it therefore cannot establish that these cases ran against Revision 1105.

## 5. Relationships

- Implementation: `sdk/io/`
- Test registration: the adjacent `CMakeLists.txt` and shared testcase harness.

## 6. References

- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/testcase_lexer.cpp`
- `test/testcase/io/parser/testvector_parser.cpp`
- `test/testcase/io/parser/testvector_parser.yml`
- `test/testcase/io/parser/asn1module.cpp`
- `test/testcase/io/parser/asn1module.hpp`
