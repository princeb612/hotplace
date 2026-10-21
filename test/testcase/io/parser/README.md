## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1105                  │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```

# Parser Testcases

## 1. Role

This directory contains direct tests for the lexical analyzer and parser engines, parser-table import, YAML-driven parser test vectors, and an ASN.1 module-boundary reducer experiment. These are related parsing tools, but they do not all exercise the same layer: lexer tests validate tokenization; parser tests validate grammar execution; the YAML vector test validates module-range detection and switching signals.

## 2. Test model

- `testcase_lexer.cpp` tests lexical tokenization, token options, and ASN.1-style hex-string handling.
- `testcase_parser.cpp` exercises ASN.1 notation with LALR and GLR parser instances, both runtime-built and imported; it also contains the direct `asn1notation.ptb` import case and the Aho–Corasick reducer test.
- `testvector_parser.cpp` loads `testvector_parser.yml`, runs the module-boundary reducer, and compares expected ranges for module clauses and level-/edge-trigger behavior.
- `asn1module.cpp` / `asn1module.hpp` provide helper grammar/reducer definitions and the shared `test_asn1parser()` test helper.
- `testvector_parser.yml` supplies data-driven input and expected ranges for the reducer path.

## 3. Example: follow one input through the layers

For tokenization, start at `testcase_lexer.cpp::test_lexer()`: the same ASN.1 sample is tokenized under two configurations, and the test asserts different token counts. Continue into `lexical_analyzer_parse.cpp` to see how registered tokens and options affect recognition.

For grammar parsing, start at `testcase_parser.cpp::test_asn1_notation()`. The function obtains four parser instances (LALR build/import and GLR build/import), checks readiness, and runs shared notation vectors through them. For a minimal import path, `test_load_parsingtable()` reads `asn1notation.ptb` and parses `Type1 ::= VisibleString`. Follow `test_asn1parser()` in `asn1module.hpp` and the engine's `parse()` implementation to connect input, parser actions, and optional parse-tree output.

For module-boundary recognition, start at `testvector_parser.cpp::test_yaml_testvector_parser()`. It loads YAML vectors, runs the Aho–Corasick reducer against the ASN.1 text, then compares discovered ranges with expected module-header/export/import ranges and checks level-/edge-trigger behavior. This is a separate pre-parsing aid rather than a replacement for the grammar parser.

## 4. Test and verification status

### 4.1 Source-level coverage

The listed functions and assertions establish what these sources intend to check. They do not establish that every production, conflict case, malformed input, or error-recovery path is covered. For a specific grammar change, inspect the relevant vector and its expected outcome alongside the production and token mapping being changed.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv for the entire `io` group. There is no separate `io/parser` row, so these totals must not be attributed to the parser tests alone. The report does not independently identify the tested source commit or exact build configuration. The documentation basis is Revision 1105, distinct from the last known report context. This documentation update did not rebuild or execute the test suite.

## 5. Relationships

- Implementation: `sdk/io/parser/`
- Higher-level consumer: `sdk/io/asn.1/`
- Test registration and shared harness: the surrounding testcase CMake configuration and `test/testcase/io/sample.hpp`.

## 6. References

- `testcase_lexer.cpp`
- `testcase_parser.cpp`
- `testvector_parser.cpp`
- `testvector_parser.yml`
- `asn1module.cpp`, `asn1module.hpp`
