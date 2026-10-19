## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# nostd

## 1. Role

### Introduction

`sdk/base/nostd` is hotplace's C++11-oriented STL-style utility layer. It provides project-owned containers, value/range abstractions, binary helpers, traits and utility code used by higher-level SDK modules.

## 2. Model

The component model is described by the implementation and retained subsections below.

## 3. Important behavior and lifetime

### Documents

- [Containers](containers.md) — sequence, tree, set and priority-queue structures
- [Binary utilities](binary.md) — byte sequences and integer/floating-point serialization helpers
- [Ranges](range.md) — intervals, range operations and range-oriented helpers
- [Bit set](bit_set.md) — bounded integer membership represented as bits
- [Runtime set facade](set.md) — runtime selection between numeric range and string set backends
- [Range set](range_set.md) — normalized numeric/ordered range operations
- [String set](string_set.md) — literal strings, string ranges, FROM and regex operations
- [Key/value](keyvalue.md) — lightweight key/value representation
- [Exceptions](exception.md) — project exception abstraction
- [Traits](traits.md) — type traits and encoding/formatting adapters
- [Utility helpers](utility.md) — conversion, casting and miscellaneous helpers
- [Deferred value](value.md) — value/future/promise-backed deferred values

### Tests

- `test/testcase/base/nostd/` — individual container and utility testcases
- [Testcase overview](../../../test/testcase/base/nostd/testcase_nostd.md) — coverage and report-based execution evidence

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

`nostd` is infrastructure rather than a single subsystem. Its range/set facilities are consumed by ASN.1 constraint evaluation; its binary helpers support byte-oriented code; its traits and utilities support templates across the SDK.

## 6. References

### Source

- `sdk/base/nostd/`
