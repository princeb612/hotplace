## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ASN.1 runtime testcase directory

## 1. Role

This directory groups tests and documentation for ASN.1 module representation, parsing, and semantic publishing.

## 2. Test model

The runtime testcase sources are `testcase_parser.cpp` and `testcase_publish.cpp`; module behavior is also exercised from the main ASN.1 testcase sources. The original document links the three topic documents and related areas.

### Preserved source material

Runtime ASN.1 module representation used after parsing/loading, including weakly typed and strongly typed object flows.

### Documents

- [Module implementation record](asn1_module.md)
- [ASN.1 parser](asn1_parser.md)
- [ASN.1 publisher](asn1_publisher.md)
- [Runtime examples](../../../../sdk/io/asn.1/runtime/runtime-examples.md)

### Related areas

- `../basic/` — type/tag/constraint definitions
- `../loader/` — loading flow
- `../compiler/` — compiler/source-generation direction
- `../../parser/` — syntax parsing

### Related tests

- `test/testcase/asn.1/runtime/`
- `test/testcase/asn.1/`

## 3. Example: source-specific testcase path

`test_asn1parser()` feeds ASN.1 assignments and constraint notation into an LALR(1) parser. `test_publish_babystep()` captures a staged parser → parse-tree → module semantic-construction experiment. Publisher and module tests also cover basics and constraints.

## 4. Test and verification status

### 4.1 Source-level coverage

- **O** — parser source contains a broad notation table, including types, tags, constructed forms, and constraints.
- **O** — publisher tests are split into basics and constraints.
- **△** — the presence of a staged experiment does not imply all compiler/loader/code-generation paths are complete.

### 4.2 Documentation and verification status

The suite report is aggregate only. It does not identify which runtime functions executed in a specific run or the run’s source revision and environment.

## 5. Relationships

- [`asn1_module.md`](asn1_module.md) — module representation
- [`asn1_parser.md`](asn1_parser.md) — grammar and parser tests
- [`asn1_publisher.md`](asn1_publisher.md) — semantic publishing tests

## 6. References

- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`
- `sdk/io/asn.1/runtime/`
