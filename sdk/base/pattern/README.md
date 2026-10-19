## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Pattern

## 1. Role

### Introduction

`sdk/base/pattern` contains reusable matching and indexing algorithms. The implementations solve different problems and should not be presented as one interchangeable search engine.

## 2. Model

The component model is described by the implementation and retained subsections below.

## 3. Important behavior and lifetime

### Documents

- [Aho-Corasick](aho_corasick.md) — multi-pattern automaton, wildcard extension and parser-oriented reducer
- [KMP](kmp.md) — single-pattern matching
- [Trie](trie.md) — prefix-oriented storage and lookup
- [Suffix tree and Ukkonen](suffix-tree-ukkonen.md) — suffix indexing and construction
- [Wildcard matching](wildcard.md) — wildcard matching and longest-common-prefix behavior
- [Regular expressions](regex.md) — regex wrapper/context and configured backend

### Tests

- `test/testcase/base/pattern/` — testcase and test-vector sources
- [Pattern testcase overview](../../../test/testcase/base/pattern/testcase_pattern.md)

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

- `sdk/io/parser/` — parser/token processing; the Aho-Corasick reducer provides token grouping/reduction facilities
- `sdk/io/string/` — URL parsing uses the regex facility

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
