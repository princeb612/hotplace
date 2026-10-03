# t_set_runtime

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`t_set_runtime<T>` is the runtime-facing set abstraction used when the concrete representation depends on the value type.

Its important role in hotplace is not to implement a third kind of set. It selects the appropriate concrete set implementation and exposes one common operation surface to callers such as the ASN.1 constraint evaluator.

## Concrete representation

```text
                 t_set_runtime<T>
                        |
                 concrete_set_t
                        |
              +---------+---------+
              |                   |
       T == std::string      integral / floating
              |                   |
              v                   v
         string_set       t_range_set<t_range_value<T>>
```

The selection is made at compile time with `std::conditional`:

- `std::string` → `string_set`
- integral type → `t_range_set<t_range_value<T>>`
- floating-point type → `t_range_set<t_range_value<T>>`

The public interface therefore lets the evaluator work with `insert`, `insert_range`, `erase`, `union_with`, `intersect_with`, `erase_from`, `invert`, and membership queries without knowing which concrete set is underneath.

## Why this layer exists

The ASN.1 constraint model has constraints that naturally describe sets of permitted values:

```text
SINGLE-VALUE   → one member
RANGE          → interval / value range
UNION          → S1 ∪ S2
INTERSECTION   → S1 ∩ S2
EXCEPT         → S1 - S2
ALL EXCEPT     → complement of S
```

The evaluator can construct and combine these sets through one type-independent interface.

```text
ASN.1 constraint tree
          |
          v
asn1_constraint_evaluator<T>
          |
          | get_result_set()
          v
   t_set_runtime<T>
          |
     +----+----+
     |         |
 numeric      string
     |         |
     v         v
 range_set  string_set
```

This is the key connection between `sdk/base/nostd` and the ASN.1 semantic layer: the set implementation remains a generic `nostd` facility, while ASN.1 supplies the meaning of the operations.

## Source-level evaluator boundary

The evaluator stores a `t_set_runtime<T>` directly and returns it through `get_result_set()`. This makes the dependency direction explicit:

```text
sdk/io/asn.1/basic/visitor
        │
        ▼
asn1_constraint_evaluator<T>
        │
        ▼
sdk/base/nostd/t_set_runtime<T>
        │
   ┌────┴────┐
   ▼         ▼
range_set  string_set
```

The `nostd` layer knows how to construct and combine sets. The ASN.1 visitor layer decides what a `UNION`, `INTERSECTION`, `EXCEPT`, `ALL EXCEPT`, `SIZE`, `FROM` or other supported constraint means.

## ASN.1 constraint composition

Nested constraints are evaluated into temporary runtime sets and then combined.

```text
             asn1_constraint_union
                    |
             +------+------+
             |             |
             v             v
        evaluator A    evaluator B
             |             |
            set A         set B
             |             |
             +------+------+
                    |
                union_with()
                    |
                    v
                  set C
```

The same pattern is used for `intersect_with()` and `erase_from()` for the corresponding constraint forms. `ALL EXCEPT` is represented by `invert()`.

## Supported value domains

`type()` exposes the runtime domain as:

- `integral`
- `real`
- `literal`

This keeps the semantic evaluator aware of the ASN.1 value category while the concrete set implementation remains hidden behind `_target`.

## Relationship with the lower-level sets

### `t_range_set<t_range_value<T>>`

Used for ordered numeric domains. It provides interval handling, open/closed endpoints, `MIN`/`MAX`, merging, subtraction, intersection, and complement.

See [range_set](range_set.md).

### `string_set`

Used for `std::string`. In addition to literal membership and string ranges, it supports `FROM`-style substring checks and regular-expression matching.

See [string_set](string_set.md).

## Tests

The common runtime façade is exercised together with both concrete implementations in:

- `test/testcase/base/nostd/testcase_set.cpp`

The test covers `t_set_runtime<int>`, `t_set_runtime<double>`, and `t_set_runtime<std::string>`, including union, subtraction, intersection, range operations, and membership.

## Related source

- `sdk/base/nostd/set.hpp`
- `sdk/base/nostd/range_set.hpp`
- `sdk/base/nostd/string_set.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.hpp`
