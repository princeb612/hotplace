## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# pattern testcase directory

## 1. Role

### Introduction

This directory contains testcases and test vectors for the algorithms in `sdk/base/pattern/`.

### Detailed overview

- [Pattern testcase overview](testcase_pattern.md)

## 2. Test model

The testcase-to-module mapping is summarized by the retained source descriptions below.

## 3. Example: representative testcase flow

No standalone example was identified in the existing material; see source-level coverage for representative testcase functions.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Test sources

- `testcase_aho_corasick.cpp`, `testcase_aho_corasick_wildcard.cpp`
- `testcase_kmp.cpp`, `testcase_trie.cpp`
- `testcase_suffixtree.cpp`, `testcase_ukkonen.cpp`, `testcase_wildcard.cpp`
- `testvector_ahocorasick.cpp`, `testvector_ahocorasick.yml`
- `testvector_kmp.cpp`, `testvector_kmp.yml`
- `testvector_regex.cpp`, `testvector_regex.yml`

### 4.2 Documentation and verification status

#### Execution evidence

The supplied `test/testcase/base/report` contains named groups for KMP, Aho-Corasick, trie, suffix tree, Ukkonen, wildcard and regular expressions. These counts are report entries, not unique test-function counts.

## 5. Relationships

Related implementation modules and testcase documents are listed in References where available.

## 6. References

Source paths and report provenance are recorded where available.
