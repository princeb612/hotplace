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

# t_range_set

## 1. Role

### Introduction

`t_range_set` is hotplace's generic set implementation for ordered values represented as individual points and intervals. It is a general `nostd` utility, not an ASN.1-specific class.

It is also the numeric backend selected by `t_set_runtime<T>` for integral and floating-point values.

### Role in the set engine

The important distinction is that `t_range_set` knows how to represent and manipulate ranges, while the ASN.1 layer gives those operations their constraint semantics.

## 2. Data Model

### Backend selection

The runtime facade selects its concrete set implementation by value type: integral and floating-point values use `t_range_set<t_range_value<T>>`, while `std::string` uses `string_set`.

```text
ASN.1 constraint object tree
            │
            ▼
 asn1_constraint_evaluator<T>
            │
            ▼
      t_set_runtime<T>
            │
      ┌─────┴─────┐
      ▼           ▼
 numeric values  string values
      │           │
      ▼           ▼
 t_range_set   string_set
```

### Representation

`t_interval<T>` stores `begin`, `end`, and independent open/closed flags for both endpoints. Its constructor orders the supplied endpoints. `t_range_value<T>` wraps a value with a range-value kind and supports special bounds such as `MIN` and `MAX`.

`t_range_set<T>` stores intervals in `_arr` (`std::vector<t_interval<T>>`), a `_status` flag that records pending modifications, an `_invert` flag for complemented membership, and a `critical_section` protecting operations that use the internal lock.

```text
t_range_set<T>
├── _arr: vector<t_interval<T>>
│     ├── begin / end
│     └── begin_flag / end_flag
├── _status: modified flag
├── _invert: membership complement
└── _lock: critical_section
```

```text
closed                 open
[1, 5]                 (1, 5)

mixed endpoints
[1, 5)       (1, 5]

special bounds
[MIN, 10]
[10, MAX)
```


## 3. Behavior Model

Normalization is lazy: mutating operations mark the set as modified, and merge-related operations sort intervals by their lower bound and combine mergeable neighbors before clearing the modified flag. For integral types, adjacent values can be merged when the ranges are contiguous. For floating-point values, endpoint openness/closedness matters because there is no discrete `next` integer value. This affects normalization and whether two intervals can be combined without changing membership.

### Core operations

The implementation supports the set operations needed by constraint composition:

```text
insert / add
      |
      +---- merge overlapping or adjacent intervals

union_with()       A ∪ B
intersect_with()   A ∩ B
erase_from()       A - B
invert()           complement of A
contains()         membership query
```

The normalized view avoids retaining redundant overlapping intervals after the merge step; callers should not assume every mutation eagerly rewrites `_arr` into normalized order.

### Why ASN.1 uses it

ASN.1 constraints naturally describe ordered value domains:

```text
INTEGER (1..10)
INTEGER (1..10 | 20..30)
INTEGER (1..100 EXCEPT 50..60)
```

These become set operations rather than ad-hoc boolean checks.

```text
RANGE
  1..10
     |
     v
  range_set

UNION
  A ∪ B
     |
     v
  union_with()

EXCEPT
  A - B
     |
     v
  erase_from()
```

This makes the same machinery useful for both direct membership tests and composition of nested ASN.1 constraints.

## 5. Relationships

- `test/testcase/base/nostd/testcase_set.cpp` exercises `t_range_set` merging, subtraction, equality, and QUIC ACK-range use cases.

### Role in the set engine

`asn1_constraint_evaluator<T>::get_result_set()` exposes the runtime set, while `t_set_runtime<T>` selects the concrete backend. `t_range_set` therefore implements numeric-domain operations; it does not interpret ASN.1 syntax itself. String-valued constraints use the separate `string_set` backend.

### Generic reuse

Although ASN.1 is an important consumer, `t_range_set` is not tied to ASN.1. The source comments also identify QUIC ACK ranges as a representative use case, and the range-set test suite exercises the data structure independently.

This separation is intentional:

```text
sdk/base/nostd/range_set.hpp
        |
        +---- generic range/set operations
        |
        +---- ASN.1 constraint backend
        |
        +---- other range-oriented SDK uses
```

`range_set.hpp` implements normalized range operations using the range primitives in `range.hpp`; `set.hpp` is the higher-level runtime facade. ASN.1 constraint evaluation consumes this representation under `sdk/io/asn.1/basic/semantic/constraints/`, but the ASN.1 layer owns the meaning of each constraint.

## 6. References

No external references are listed.
