## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```

# ASN.1 runtime testcase directory

## 1. Role

This directory tests the runtime-facing stages after generic syntax parsing: parsing ASN.1 notation with the ASN.1 grammar, publishing parse-tree reductions into semantic module/type objects, and inspecting the resulting runtime representation.

## 2. Test model

- `testcase_parser.cpp` exercises `asn1_parser` using notation samples for assignments, constructed types, tags, and constraints.
- `testcase_publish.cpp` covers publisher basics and constraints, including the staged `test_publish_babystep()` path.
- Main-suite sources such as `test/testcase/asn.1/testcase_basic2.cpp` also exercise referenced-type definitions and linkage; the runtime directory is not the only source of runtime-model coverage.

### Documents

- [Module implementation record](asn1_module.md)
- [ASN.1 parser](asn1_parser.md)
- [ASN.1 publisher](asn1_publisher.md)
- [Runtime examples](../../../../sdk/io/asn.1/runtime/runtime-examples.md)

## 3. Example: parse tree to published module

Start with `testcase_parser.cpp::test_asn1parser()` to see ASN.1 notation passed through the parser. Then follow `testcase_publish.cpp::test_publish_babystep()`, which captures the staged parser → parse tree → publisher/semantic construction experiment. The publisher’s basic and constraint cases are separated so a failure can be attributed more narrowly than a single end-to-end assertion.

At the wider suite level, `test/testcase/asn.1/loader/testcase_loader.cpp` demonstrates file loading followed by publisher construction, including `EXPORTS`/`IMPORTS` and `is_resolvable()` checks for imported definitions.

## 4. Test and verification status

### 4.1 Source-level coverage

- **Present:** notation parsing, basic semantic publishing, and constraint publishing have dedicated source paths.
- **Boundary:** these tests do not by themselves prove that all ASN.1 productions, malformed inputs, error recovery, or all compiler/loader paths are covered.
- **Boundary:** parameterized direct semantic specialization and the parser → loader → publisher integration probe are distinct paths; do not infer complete parameterized support from either one alone.

### 4.2 Documentation and verification status

The available ASN.1 report is aggregate at the parent-suite level and does not isolate these runtime functions or independently identify the exact source revision and environment. The last known report context is Revision 1104 · MinGW64/GCC · CTest; this document's source basis is Revision 1105. This documentation update did not execute the tests.

## 5. Relationships

- [Module implementation record](asn1_module.md) — module representation and symbol resolution
- [ASN.1 parser](asn1_parser.md) — grammar and parser-facing behavior
- [ASN.1 publisher](asn1_publisher.md) — semantic reconstruction
- [Implementation runtime overview](../../../../sdk/io/asn.1/runtime/README.md)

## 6. References

- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`
- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `sdk/io/asn.1/runtime/`
