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

# Range utilities

## 1. Role

The range headers represent intervals and provide supporting range-oriented operations. `range.hpp` defines interval/range primitives; `range_set.hpp` builds normalized set operations on top of range values. The distinction matters: an interval is a range description, while a range set combines multiple permitted regions.

## 2. Data Model

### Range representations

- `t_range_t<T>` stores two normalized endpoints and orders ranges by begin then end. Its `width()` is the endpoint difference, not an element count.
- `range_t` is the `size_t` specialization used for source positions and other index ranges. The base range type does not encode open/closed endpoints.
- `t_interval<T>` in `range_set.hpp` adds `begin_flag` / `end_flag` so membership can distinguish [a,b], (a,b), and mixed endpoints.
- `range_traits<T>` controls whether adjacent ranges can merge and how `next()` / `prev()` are computed. Integral ranges can merge across adjacent integer values; floating-point ranges merge on overlap because there is no discrete next value.

Endpoint openness and closedness affect membership. The numeric range-set implementation also distinguishes integral adjacency from floating-point overlap when deciding whether ranges can merge.

## 3. Behavior Model

### Range-set operations

```text
insert / add ─► normalize and merge compatible intervals
union / intersection / subtraction / inversion ─► derived interval set
contains() ─► membership result
```

The interval-set operation details are described in [range_set.md](range_set.md).

## 4. Relationships

- `range.hpp` defines range primitives; `range_set.hpp` builds normalized interval operations from them, while `set.hpp` provides the runtime facade that selects a set backend.
- `testcase_set.cpp` exercises the set family. The ASN.1 constraint evaluator in `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.hpp` is a higher-level consumer of runtime set operations; ASN.1 owns the constraint semantics.
