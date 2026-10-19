## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Suffix tree and Ukkonen construction

## 1. Role

`suffixtree.hpp` and `ukkonen.hpp` provide suffix-tree-oriented indexing. The suffix tree represents suffixes of a text so that substring-oriented queries can use the index; Ukkonen's algorithm is the construction method represented by the companion implementation.

## 2. Model

```text
input text
    |
    v
suffix-tree construction
    |
    v
suffix-oriented index
    |
    v
substring / suffix queries
```

This page keeps the data structure and its construction algorithm together because the source tree places them side by side, but they remain distinct concepts: a suffix tree is the resulting index, while Ukkonen describes how it is built.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source tests

- `testcase_suffixtree.cpp` tests suffix-tree behavior.
- `testcase_ukkonen.cpp` tests the construction algorithm.

The base report lists 9 pass entries for `suffix tree` and 11 pass entries for `ukkonen algorithm`.

## 5. Relationships

- `sdk/base/pattern/suffixtree.hpp`
- `sdk/base/pattern/ukkonen.hpp`
- `test/testcase/base/pattern/testcase_suffixtree.cpp`
- `test/testcase/base/pattern/testcase_ukkonen.cpp`

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
