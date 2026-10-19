## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Range utilities

## 1. Role

The range headers represent intervals and provide supporting range-oriented operations. `range.hpp` defines interval/range primitives; `range_set.hpp` builds normalized set operations on top of range values. The distinction matters: an interval is a range description, while a range set combines multiple permitted regions.

## 2. Model

```text
range / interval
       |
       v
range_set representation
       |
       +--> insert / merge
       +--> intersection / subtraction
       +--> membership query
```

Endpoint openness and closedness affect membership. The numeric range-set implementation also distinguishes integral adjacency from floating-point overlap when deciding whether ranges can merge.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source tests

`testcase_set.cpp` checks interval equality, merging, subtraction, intersection, open/closed endpoints and special `MIN`/`MAX` values. See [range_set](range_set.md) for the concrete set model.

## 5. Relationships

- `sdk/base/nostd/range.hpp`
- `sdk/base/nostd/range_set.hpp`
- `sdk/base/nostd/set.hpp`
- `test/testcase/base/nostd/testcase_set.cpp`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.hpp` — higher-level consumer of runtime set operations

## 6. References

- Interval arithmetic and set operations; this document describes the repository's implementation rather than a separate external range library.
