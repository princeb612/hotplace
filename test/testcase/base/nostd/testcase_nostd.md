## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# nostd testcase overview

## 1. Role

This document maps the `sdk/base/nostd` utilities to the test sources that exercise them. It records source-level coverage separately from execution results.

## 2. Test model

The testcase-to-module mapping is summarized by the retained source descriptions below.

## 3. Example: representative testcase flow

This document does not duplicate a standalone program. The representative testcase functions and their assertion strength are described under Source-level coverage.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Test-to-module map

| Test source | Primary area evidenced by its name/content |
|---|---|
| `testcase_binary.cpp` | Binary append/conversion helpers |
| `testcase_bitset.cpp` | Bounded bit-set operations |
| `testcase_set.cpp` | Numeric ranges, runtime set facade, string set and set operations |
| `testcase_exception.cpp` | Exception abstraction |
| `testcase_findlte.cpp` | Find-less-than-or-equal helper |
| `testcase_int.cpp` | Integer conversion helpers |
| `testcase_narrowcast.cpp` | Narrowing-cast behavior |
| `testcase_avltree.cpp`, `testcase_btree.cpp`, `testcase_tree.cpp` | Tree structures |
| `testcase_list.cpp`, `testcase_map.cpp`, `testcase_pq.cpp`, `testcase_vector.cpp` | Container families |

#### Cross-check observations

- `testcase_set.cpp` contains explicit comparisons for interval contents and membership, including open/closed endpoints and special `MIN`/`MAX` values.
- `testcase_bitset.cpp`'s report group has 11 `expt` entries. Inspect the corresponding test/log context before assigning a semantic interpretation to this label.
- A passing report row is evidence of execution status for that reported case, not a proof of exhaustive coverage.

### 4.2 Documentation and verification status

#### Documentation completeness

**Status: Partial.** The direct source files and main test groupings are mapped, but the current test set is not a formal statement of complete behavioral coverage for every public method in `nostd`.

#### Verification completeness

**Status: Partial.** The source report contains explicit expected-value checks for many range/set behaviors. It also records 11 `expt` entries in the `bitset` group; that original classification is retained and is not silently recoded as pass or fail. A test group passing does not establish that all boundary cases are covered.

#### Runtime execution

**Status: Report available.** The supplied `test/testcase/base/report` records these relevant groups:

| Report group | pass | expt | fail | skip | triv |
|---|---:|---:|---:|---:|---:|
| `binary` | 17 | 0 | 0 | 0 | 0 |
| `bitset` | 8 | 11 | 0 | 0 | 0 |
| `rangeset` | 73 | 0 | 0 | 0 | 0 |
| `string_set` | 100 | 0 | 0 | 0 | 0 |
| `range` | 4 | 0 | 0 | 0 | 0 |
| `AVL tree` | 3 | 0 | 0 | 0 | 0 |
| `binary tree` | 7 | 0 | 0 | 0 | 0 |
| `exception` | 1 | 0 | 0 | 0 | 0 |
| `find_lessthan_or_equal` | 11 | 0 | 0 | 0 | 0 |
| `atoi` | 6 | 0 | 0 | 0 | 0 |
| `htoi` | 3 | 0 | 0 | 0 | 0 |
| `list` | 5 | 0 | 0 | 0 | 0 |
| `maphint` | 3 | 0 | 0 | 0 | 0 |
| `narrow cast` | 3 | 0 | 0 | 0 | 0 |
| `binaryheap` | 4 | 0 | 0 | 0 | 0 |
| `tree` | 1 | 0 | 0 | 0 | 0 |
| `vector` | 5 | 0 | 0 | 0 | 0 |
| `value - not exception-sensitive future-promise pattern` | 8 | 0 | 0 | 0 | 0 |

The report does not identify the operating system, compiler, build configuration or source revision. Those fields remain unspecified rather than inferred.

## 5. Relationships

### Related implementation documents

- `sdk/base/nostd/binary.md`
- `sdk/base/nostd/bit_set.md`
- `sdk/base/nostd/range.md`
- `sdk/base/nostd/set.md`
- `sdk/base/nostd/range_set.md`
- `sdk/base/nostd/string_set.md`

## 6. References

Source paths and report provenance are recorded where available.
