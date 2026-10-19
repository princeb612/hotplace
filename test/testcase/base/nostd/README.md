## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# nostd testcase directory

## 1. Role

### Introduction

This directory tests the project-owned containers and utility types under `sdk/base/nostd/`.

### Detailed overview

- [nostd testcase overview](testcase_nostd.md)

## 2. Test model

The testcase-to-module mapping is summarized by the retained source descriptions below.

## 3. Example: representative testcase flow

No standalone example was identified in the existing material; see source-level coverage for representative testcase functions.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Test sources

- `testcase_binary.cpp`, `testcase_bitset.cpp`
- `testcase_avltree.cpp`, `testcase_btree.cpp`, `testcase_list.cpp`, `testcase_map.cpp`, `testcase_pq.cpp`, `testcase_set.cpp`, `testcase_tree.cpp`, `testcase_vector.cpp`
- `testcase_exception.cpp`, `testcase_findlte.cpp`, `testcase_int.cpp`, `testcase_narrowcast.cpp`

### 4.2 Documentation and verification status

#### Execution evidence

The supplied `test/testcase/base/report` includes groups such as `binary`, `rangeset`, `string_set`, and `bitset`. The report is a run record, not proof that every behavior of every header is covered.

## 5. Relationships

Related implementation modules and testcase documents are listed in References where available.

## 6. References

Source paths and report provenance are recorded where available.
