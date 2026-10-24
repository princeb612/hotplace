## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
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

| Type | Representation | Structural distinction |
|---|---|---|
| `t_vector<T>` | Contiguous `new[]` allocation with size and capacity | Project-owned vector-like sequence; not `std::vector`. |
| `t_list<T>` | Doubly linked nodes with bidirectional iterators | Node-based sequence rather than contiguous storage. |
| `t_btree<T>` | Binary-search-tree nodes with left/right links | Despite the historical name, this is a binary search tree, not a multiway B-tree. |
| `t_avltree<T>` | Binary-search-tree nodes with stored height | Stores height metadata used by AVL balancing. |
| `t_tree<T>` | General tree nodes with parent/child/sibling relationships | Represents hierarchy rather than ordered key lookup. |
| `t_binary_heap<T>` | Array-backed binary min-heap | Heap-ordered sequence; distinct from a fully sorted array. |
| `t_set_runtime<T>` | Runtime-selected concrete set | Uses `t_range_set` for numeric domains and `string_set` for strings; see [set](set.md). |
| `t_bit_set` | Bounded integer membership encoded as bits | Compact membership representation, not an ordered tree container. |

## 3. Behavior Model

### Mutation and algorithm behavior

- `t_vector<T>` growth may allocate a new array and move elements, so callers must not assume `std::vector` invalidation details. Copying retains source elements; moving transfers the sequence and leaves the moved-from vector empty.
- `t_list<T>` insertion and removal operate on linked nodes. Iterator validity depends on whether the referenced node is removed.
- `t_btree<T>` is not self-balancing; ordered operations do not maintain AVL-style height bounds.
- `t_avltree<T>` uses insertion/removal balancing and rotations to maintain height balance. Duplicate insertion is treated as an existing key rather than adding another entry.
- `t_binary_heap<T>::top()` returns the smallest element under its ordering; `push()` percolates upward and `pop()` restores heap order.

### Main groups

- `vector.hpp`, `list.hpp` — sequence containers
- `set.hpp`, `btree.hpp`, `avltree.hpp`, `tree.hpp` — ordered/tree-oriented containers
- `pq.hpp` — priority queue
- `bit_set.hpp` — compact bit-set operations
- `range.hpp`, `range_set.hpp` — range collections and range-set operations

`set`, tree and range structures are also used by higher-level matching/search code, so they are infrastructure rather than protocol-specific implementations.

## 5. Relationships
- [Range set](range_set.md) and [string set](string_set.md) implement range/value-set operations; they are separate from the tree and sequence containers.
- [Runtime set facade](set.md) selects the numeric or string backend based on the value type.
- `sdk/base/pattern/trie.hpp` provides a prefix trie for sequence matching; it is distinct from the ordered search trees in this document.
- `sdk/io/asn.1/basic/semantic/constraints/` consumes the range/set family to evaluate ASN.1 constraints.
- `test/testcase/base/nostd/` contains dedicated source tests for AVL tree, B-tree, list, set, tree, range, and vector behavior (`testcase_avltree.cpp`, `testcase_btree.cpp`, `testcase_list.cpp`, `testcase_set.cpp`, `testcase_tree.cpp`, `testcase_range.cpp`, and `testcase_vector.cpp`).

## 6. References

No external references are listed.
