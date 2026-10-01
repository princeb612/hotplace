# t_range_set

`t_range_set` is hotplace's generic set implementation for ordered values represented as individual points and intervals. It is a general `nostd` utility, not an ASN.1-specific class.

It is also the numeric backend selected by `t_set_runtime<T>` for integral and floating-point values.

## Role in the set engine

```text
                 ASN.1 semantic layer
                         |
                         v
              asn1_constraint_evaluator
                         |
                         v
                  t_set_runtime<T>
                         |
             integral / floating-point
                         |
                         v
             t_range_set<t_range_value<T>>
```

The important distinction is that `t_range_set` knows how to represent and manipulate ranges, while the ASN.1 layer gives those operations their constraint semantics.

## Representation

A range is represented by an interval with explicit endpoint flags. `t_range_value<T>` additionally allows special boundary values such as `MIN` and `MAX`.

```text
closed                 open
[1, 5]                 (1, 5)

mixed endpoints
[1, 5)       (1, 5]

special bounds
[MIN, 10]
[10, MAX)
```

For integral types, adjacent values can be merged when the ranges are contiguous. For floating-point values, endpoint openness/closedness matters because there is no discrete `next` integer value.

## Core operations

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

The internal representation is kept normalized so that overlapping ranges can be merged instead of being retained as many redundant intervals.

## Why ASN.1 uses it

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

## Generic reuse

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

## Tests

`test/testcase/base/nostd/testcase_set.cpp` covers:

- basic range insertion and merging
- single values mixed with ranges
- subtraction and intersection
- `MIN` / `MAX`
- open and closed endpoints
- integral and floating-point domains
- `t_range_value<T>` special boundary representation

## Related source

- `sdk/base/nostd/range_set.hpp`
- `sdk/base/nostd/range.hpp`
- `sdk/base/nostd/set.hpp`
- `sdk/io/asn.1/basic/semantic/constraints/`
