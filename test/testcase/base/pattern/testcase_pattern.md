## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Pattern testcase overview

## 1. Role

This page maps pattern implementations to their testcase sources and summarizes the supplied base report. Matching algorithms are documented separately because their behavior and intended use differ.

## 2. Test model

The testcase-to-module mapping is summarized by the retained source descriptions below.

## 3. Example: representative testcase flow

This document does not duplicate a standalone program. The representative testcase functions and their assertion strength are described under Source-level coverage.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Test-to-module map

| Test source / report group | Main area |
|---|---|
| `testcase_kmp.cpp`, `testvector_kmp.*` | Single-pattern KMP matching |
| `testcase_trie.cpp` | Trie operations |
| `testcase_suffixtree.cpp` | Suffix-tree behavior |
| `testcase_ukkonen.cpp` | Ukkonen construction |
| `testcase_aho_corasick.cpp`, `testvector_ahocorasick.*` | Aho-Corasick matching and reducer behavior |
| `testcase_aho_corasick_wildcard.cpp` | Wildcard extension over Aho-Corasick |
| `testcase_wildcard.cpp` | Wildcard matching and LCP behavior |
| `testvector_regex.*` | Regular-expression cases |

#### Cross-check observations

- KMP tests assert the expected index `0xa` for multiple element representations.
- Aho-Corasick wildcard tests and the standalone wildcard test exercise related but separate implementations.
- Regex report counts indicate recorded executions; they do not by themselves prove equivalence across all configured regex backends.

### 4.2 Documentation and verification status

#### Documentation completeness

**Status: Partial.** The principal implementation and test-vector files are mapped. This overview does not claim that every algorithmic edge case or every backend-specific regex behavior is covered.

#### Verification completeness

**Status: Partial.** KMP's source testcase includes explicit assertions for match positions across byte, struct and pointer/comparator cases. The other groups have their own direct tests and vectors, but coverage completeness should be judged per behavior rather than by the aggregate count alone.

#### Runtime execution

**Status: Report available.** Relevant groups from the supplied `test/testcase/base/report`:

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

The report does not identify OS, compiler, build configuration or source revision. No values are inferred for those fields.

## 5. Relationships

### Related implementation documents

- `sdk/base/pattern/kmp.md`
- `sdk/base/pattern/trie.md`
- `sdk/base/pattern/suffix-tree-ukkonen.md`
- `sdk/base/pattern/wildcard.md`
- `sdk/base/pattern/regex.md`
- `sdk/base/pattern/aho_corasick.md`

## 6. References

Source paths and report provenance are recorded where available.
