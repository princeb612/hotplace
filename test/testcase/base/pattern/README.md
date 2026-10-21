## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Pattern testcase directory

## 1. Role

This directory holds source-level tests and test vectors for the matching and indexing implementations in `sdk/base/pattern/`. The tests are deliberately separated by behavior: standalone wildcard matching is not the same path as wildcard-aware Aho-Corasick, and suffix-trie tests are separate from Ukkonen construction tests.

## 2. Test model

- `testcase_*.cpp` files define direct test functions and explicit assertions.
- `testvector_*.cpp` files connect table-driven inputs to the testcase framework.
- `testvector_*.yml` files provide externalized cases for vector-driven tests.
- The supplied `test/testcase/base/report` records execution groups and result counts. A report entry count is not the same as a unique assertion or test-function count, and the report does not identify its OS/compiler/build configuration.

The algorithm-to-test mapping and report snapshot are maintained in this README.

## 3. Example: KMP match position and wildcard distinction

`testcase_kmp.cpp` searches the byte sequence `abacaabaccabacabaabb` for `abacab` and asserts that the first match starts at index `0xa`. It repeats the same assertion for a vector, contiguous memory, value objects and pointer objects using a custom comparator.

The wildcard tests distinguish two contracts: `testcase_wildcard.cpp` checks one expression against one sequence, while `testcase_aho_corasick_wildcard.cpp` inserts multiple wildcard patterns into the Aho-Corasick automaton and checks all reported ranges and pattern IDs.

## 4. Test and verification status

### 4.1 Source-level coverage

| Test source / vector | Implementation and observable behavior |
|---|---|
| `testcase_kmp.cpp`, `testvector_kmp.cpp`, `testvector_kmp.yml` | KMP first-match position and alternate element/comparator representations |
| `testcase_trie.cpp` | Exact search, prefix, erase, suggestion, longest-prefix lookup, index lookup and Huffman-code scan |
| `testcase_aho_corasick.cpp`, `testvector_ahocorasick.cpp`, `testvector_ahocorasick.yml` | Multi-pattern match ranges, token grouping, sub-pattern reduction and repeat-rule processing |
| `testcase_aho_corasick_wildcard.cpp` | Wildcard-aware multi-pattern matches and ignore-case behavior |
| `testcase_wildcard.cpp` | Standalone wildcard matching over character and token/pointer sequences; test-local LCP helper |
| `testcase_suffixtree.cpp` | Explicit suffix-trie lookup |
| `testcase_ukkonen.cpp` | Ukkonen construction and suffix-tree queries |
| `testvector_regex.cpp`, `testvector_regex.yml` | Regex matching/tokenization test vectors |

Cross-check observations:

- KMP's direct testcase asserts the same match position for four data representations.
- Trie coverage checks exact-key membership and operations that consume a sequence incrementally.
- The Aho-Corasick reducer checks nested/overlapping token patterns, virtual token groups and repeat rules; its wildcard testcase exercises a distinct subclass path.
- Regex report counts do not establish identical edge-case behavior across all compiler-selected backends.

### 4.2 Report evidence and limitations

Relevant groups from the supplied `test/testcase/base/report`:

| Report group | pass | expt | fail | skip | triv |
|---|---:|---:|---:|---:|---:|
| `kmp` | 4 | 0 | 0 | 0 | 0 |
| `The Knuth-Morris-Pratt Algorithm` | 7 | 0 | 0 | 0 | 0 |
| `aho_corasick` | 2 | 0 | 0 | 0 | 0 |
| `aho_corasick (token grouping, sub-pattern reduction, and repeat-rule processing)` | 5 | 0 | 0 | 0 | 0 |
| `trie` | 24 | 0 | 0 | 0 | 0 |
| `suffix tree` | 9 | 0 | 0 | 0 | 0 |
| `ukkonen algorithm` | 11 | 0 | 0 | 0 | 0 |
| `aho_corasick + wildcards` | 1 | 0 | 0 | 0 | 0 |
| `aho_corasick + wildcards + ignore case` | 1 | 0 | 0 | 0 | 0 |
| `aho corasick` | 25 | 0 | 0 | 0 | 0 |
| `regular expression` | 80 | 0 | 0 | 0 | 0 |
| `wildcards` | 10 | 0 | 0 | 0 | 0 |

**Documentation completeness: Partial.** The principal testcase and vector files are mapped, but this does not claim exhaustive edge-case coverage for every algorithm or regex backend.

**Verification completeness: Partial.** Direct assertions are identified where visible in source. Report totals alone are not used to infer complete coverage.

**Runtime execution: Report available.** The report does not identify OS, compiler, build configuration or source revision. No values are inferred for those fields.

## 5. Relationships

- [`sdk/base/pattern/README.md`](../../../../sdk/base/pattern/README.md) — implementation directory overview.
- [`testcase_kmp.cpp`](testcase_kmp.cpp), [`testcase_trie.cpp`](testcase_trie.cpp), [`testcase_aho_corasick.cpp`](testcase_aho_corasick.cpp), [`testcase_aho_corasick_wildcard.cpp`](testcase_aho_corasick_wildcard.cpp), [`testcase_wildcard.cpp`](testcase_wildcard.cpp), [`testcase_suffixtree.cpp`](testcase_suffixtree.cpp), and [`testcase_ukkonen.cpp`](testcase_ukkonen.cpp) — direct source tests summarized in this README.
- [`testvector_kmp.cpp`](testvector_kmp.cpp), [`testvector_kmp.yml`](testvector_kmp.yml), [`testvector_ahocorasick.cpp`](testvector_ahocorasick.cpp), [`testvector_ahocorasick.yml`](testvector_ahocorasick.yml), and [`testvector_regex.yml`](testvector_regex.yml) — data-driven test inputs.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and limitations.
- Individual implementation pages link to their corresponding test sources; this directory owns test coverage and execution evidence rather than duplicating those details in SDK documentation.

## 6. References

No external book, RFC, article, or online reference is required for this directory overview. The internal testcase mapping and report evidence are linked under Relationships.
