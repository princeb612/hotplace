## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# nostd Containers

## 1. Role

### Introduction

The container side of `nostd` provides STL-like structures used where hotplace wants predictable C++11-era behavior and its own APIs.

## 2. Model

The component model is described by the implementation and retained subsections below.

## 3. Important behavior and lifetime

### Main groups

- `vector.hpp`, `list.hpp` — sequence containers
- `set.hpp`, `btree.hpp`, `avltree.hpp`, `tree.hpp` — ordered/tree-oriented containers
- `pq.hpp` — priority queue
- `bit_set.hpp` — compact bit-set operations
- `range.hpp`, `range_set.hpp` — range collections and range-set operations

`set`, tree and range structures are also used by higher-level matching/search code, so they are infrastructure rather than protocol-specific implementations.

### Tests

The corresponding testcase directory covers AVL tree, B-tree, list, map/set, priority queue, range, tree and vector behavior.

- `test/testcase/base/nostd/testcase_avltree.cpp`
- `test/testcase/base/nostd/testcase_btree.cpp`
- `test/testcase/base/nostd/testcase_list.cpp`
- `test/testcase/base/nostd/testcase_set.cpp`
- `test/testcase/base/nostd/testcase_tree.cpp`
- `test/testcase/base/nostd/testcase_range.cpp`
- `test/testcase/base/nostd/testcase_vector.cpp`

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

Related components and cross-module links are listed in References where available.

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
