## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Wildcard matching

## 1. Role

`wildcard.hpp` provides wildcard matching and the longest-common-prefix behavior exercised by the wildcard testcase. This is a separate matching model from regular expressions and from the parser-oriented Aho-Corasick reducer.

## 2. Model

```text
input text + wildcard expression
             |
             v
       wildcard matcher
             |
             v
       match / no match
```

Do not treat wildcard syntax as regex syntax; the two facilities have separate implementations and tests.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source tests

`testcase_wildcard.cpp` covers wildcard behavior. `testcase_aho_corasick_wildcard.cpp` separately covers wildcard extensions over Aho-Corasick, including ignore-case behavior. These tests exercise related but not identical implementations.

## 5. Relationships

- `sdk/base/pattern/wildcard.hpp`
- `sdk/base/pattern/aho_corasick_wildcard.hpp`
- `test/testcase/base/pattern/testcase_wildcard.cpp`
- `test/testcase/base/pattern/testcase_aho_corasick_wildcard.cpp`

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
