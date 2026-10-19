## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Utility helpers

## 1. Role

This page groups small, cross-cutting helpers that do not form a single data structure: numeric text conversion (`atoi.hpp`), project-specific casting (`cast.hpp`), miscellaneous utilities (`utility.hpp`), memory helpers (`memory.hpp`) and enum-class support (`enumclass.hpp`).

## 2. Model

```text
text / generic value
       |
       v
conversion, cast or helper API
       |
       v
caller-specific value or operation
```

These helpers are infrastructure. Their exact contracts are defined by each function and should not be generalized into one shared error or ownership policy.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from tests

`testcase_int.cpp` covers integer conversion helpers such as `atoi`/`htoi`; `testcase_narrowcast.cpp` covers narrowing-cast behavior. There is no single testcase that establishes complete coverage for every header listed on this page.

## 5. Relationships

- `sdk/base/nostd/atoi.hpp`
- `sdk/base/nostd/cast.hpp`
- `sdk/base/nostd/utility.hpp`
- `sdk/base/nostd/memory.hpp`
- `sdk/base/nostd/enumclass.hpp`
- `test/testcase/base/nostd/testcase_int.cpp`
- `test/testcase/base/nostd/testcase_narrowcast.cpp`

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
