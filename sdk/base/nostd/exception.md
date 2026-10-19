## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Exception utility

## 1. Role

`exception.hpp` and `exception.cpp` define hotplace's project exception abstraction and error-code integration. The type is used by low-level utilities to report exceptional conditions, including size/range constraints in utility classes.

## 2. Model

```text
operation detects error
        |
        v
hotplace error code / exception
        |
        v
caller handles or propagates it
```

Do not infer that every API throws: several utility methods return `return_t` error codes, while other paths explicitly construct or throw `exception` objects. The call site determines which contract applies.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example and tests

`testcase_exception.cpp` is the direct testcase file. `testcase_bitset.cpp` also exercises a bounded allocation path indirectly through the bit-set API, but its presence alone does not establish coverage of every exception code.

## 5. Relationships

- `sdk/base/nostd/exception.hpp`
- `sdk/base/nostd/exception.cpp`
- `test/testcase/base/nostd/testcase_exception.cpp`
- `sdk/base/nostd/bit_set.hpp` — throws for oversized storage allocation

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
