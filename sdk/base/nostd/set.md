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

# t_set_runtime

## 1. Role

### Introduction

`t_set_runtime<T>` is the runtime-facing set abstraction used when the concrete representation depends on the value type.

Its important role in hotplace is not to implement a third kind of set. It selects the appropriate concrete set implementation and exposes one common operation surface to callers such as the ASN.1 constraint evaluator.

## 2. Data Model

### Concrete representation

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

## 3. Behavior Model

### Why this layer exists

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

### ASN.1 constraint composition

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

### Supported value domains

`type()` exposes the runtime domain as:

- `integral`
- `real`
- `literal`

This keeps the semantic evaluator aware of the ASN.1 value category while the concrete set implementation remains hidden behind `_target`.

## 4. Relationships

- `test/testcase/base/nostd/testcase_set.cpp` provides source-level coverage for runtime set selection and set operations.

### Relationship with the lower-level sets

#### `t_range_set<t_range_value<T>>`

Used for ordered numeric domains. It provides interval handling, open/closed endpoints, `MIN`/`MAX`, merging, subtraction, intersection, and complement.

See [range_set](range_set.md).

#### `string_set`

Used for `std::string`. In addition to literal membership and string ranges, it supports `FROM`-style substring checks and regular-expression matching.

See [string_set](string_set.md).

### Source-level evaluator boundary

The evaluator stores a `t_set_runtime<T>` and exposes it through `get_result_set()`. This shows the dependency boundary without repeating the concrete-backend selection already described in the Data Model:

```text
sdk/io/asn.1/basic/visitor
        │
        ▼
asn1_constraint_evaluator<T>
        │
        │ get_result_set()
        ▼
sdk/base/nostd/t_set_runtime<T>
```

The `nostd` layer constructs and combines sets through the runtime facade. The ASN.1 visitor layer decides what a `UNION`, `INTERSECTION`, `EXCEPT`, `ALL EXCEPT`, `SIZE`, `FROM` or other supported constraint means. The facade then selects `t_range_set` or `string_set` according to the value type, as shown above.


The facade is implemented in `set.hpp`; its numeric backend is `range_set.hpp`, and its string backend is `string_set.hpp`. The ASN.1 visitor connects to the facade through `asn1_constraint_evaluator.hpp`.
## 5. References

No external references are listed.
