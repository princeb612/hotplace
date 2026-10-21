## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# nostd Containers

## 1. Role

### Introduction

The container side of `nostd` provides STL-like structures used where hotplace wants predictable C++11-era behavior and its own APIs.

## 2. Data Model

### Container implementations

| Type | Representation | Important distinction |
|---|---|---|
| `t_vector<T>` | Contiguous `new[]` allocation with size and capacity | Growth may allocate a new array and move elements; it is not `std::vector` and should not be assumed to match all invalidation details. |
| `t_list<T>` | Doubly linked nodes with bidirectional iterators | Insert/erase operates on nodes; iterator validity depends on whether the referenced node is removed. |
| `t_btree<T>` | Binary-search-tree nodes with left/right links | Despite the historical type name, this implementation is a binary search tree, not a multiway B-tree and does not rebalance itself. |
| `t_avltree<T>` | Binary-search-tree nodes with stored height | Insert/remove use AVL balancing and rotations to maintain height balance. |
| `t_tree<T>` | General tree nodes with parent/child/sibling relationships | Represents hierarchical structure rather than ordered key lookup. |
| `t_binary_heap<T>` | Array-backed binary min-heap | `top()` returns the smallest element under its ordering; `push()` percolates upward and `pop()` restores heap order. |
| `t_set_runtime<T>` | Runtime-selected concrete set | Uses `t_range_set` for numeric domains and `string_set` for strings; see [set](set.md). |
| `t_bit_set` | Bounded integer membership encoded as bits | Compact membership representation, not an ordered tree container. |

## 3. Behavior Model

The vector implementation distinguishes copying from moving a sequence: a copy retains the source elements, while a move transfers the stored sequence and leaves the moved-from vector empty. The AVL container also treats duplicate insertion as an existing key rather than creating a second entry; its focused testcase checks size stability after duplicate inserts and emptiness after removal.

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

## 4. Relationships

- [Range set](range_set.md) and [string set](string_set.md) implement range/value-set operations; they are separate from the tree and sequence containers.
- [Runtime set facade](set.md) selects the numeric or string backend based on the value type.
- `sdk/base/pattern/trie.hpp` provides a prefix trie for sequence matching; it is distinct from the ordered search trees in this document.
- `sdk/io/asn.1/basic/semantic/constraints/` consumes the range/set family to evaluate ASN.1 constraints.
- `test/testcase/base/nostd/` contains dedicated source tests for the container families, including `testcase_vector.cpp`, `testcase_list.cpp`, `testcase_btree.cpp`, `testcase_avltree.cpp`, `testcase_tree.cpp`, and `testcase_set.cpp`. The source review note below is retained separately from this runtime/test relationship.

## 6. Development Notes (for maintainer review)
The current tree special-member implementations deserve a follow-up source review. In `t_btree`, the copy constructor initializes `_size` from `other.size` rather than a call to `other.size()`, and its copy/move assignment operators do not return `*this`. In `t_avltree`, the copy constructor clones the root without copying `_size`; copy assignment also leaves `_size` unchanged, and both assignment operators omit `return *this`. The current container testcase covers insert/remove and traversal, but does not establish correct copy/assignment behavior for these tree types.
