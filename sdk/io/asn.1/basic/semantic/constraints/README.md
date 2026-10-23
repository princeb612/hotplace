## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Constraints

## 1. Role

`basic/semantic/constraints` contains the ASN.1 subtype/constraint model and evaluator path used to represent and check value-set/range restrictions. It bridges ASN.1 semantic constraints to generic runtime sets in `sdk/base/nostd`.

Keep three separate claims in view: the standard defines a notation family, the parser/publisher may construct a semantic node for a form, and the evaluator may or may not implement its runtime meaning. These are related stages, not interchangeable evidence.

## 2. Data Model

### Documents

- [ASN.1 constraints](asn1_constraints.md) — implementation record for constraint nodes and evaluation.
- [Subtype notation and value sets](subtype-notation.md) — retained developer study/reference note, not a conformance checklist.

### Runtime set backend

Constraint evaluation ultimately uses the generic set infrastructure under `sdk/base/nostd`:

## 3. Behavior Model

### Evaluation target

```text
asn1_constraint_evaluator<T>
          |
          v
    t_set_runtime<T>
       +-- t_range_set<t_range_value<T>>  (numeric / real domains)
       `-- string_set                    (string domains)
```

The evaluator walks semantic constraint nodes and accumulates the allowed domain into the type-appropriate runtime-set representation. Range and string constraints therefore need not share the same backend representation.


A typical path is:

```text
constraint notation
       |
       v
parser / semantic publisher
       |
       v
ASN.1 constraint nodes
       |
       v
asn1_constraint_evaluator<T>
       |
       | get_result_set()
       v
t_set_runtime<T>
       |
       v
value-domain membership / set operations
```

The constraint classes describe semantic operations; the evaluator executes those operations against a value-domain representation. Composition uses set algebra, including union, intersection, exclusion and complement-style operations. This path is separate from DER byte encoding.

Do not assume every constraint becomes one numeric interval, or that a notation example proves the current evaluator implements that form. When extending constraint support, trace both the publisher's construction path and the evaluator's handling of the resulting node.

## 4. Relationships
- [Constraint implementation](asn1_constraints.md) — concrete nodes, evaluator and runtime-set mapping.
- [Subtype notation](subtype-notation.md) — developer study note with examples and supported-type matrix.
- [Semantic ASN.1 model](../README.md) — where type constraints belong in the semantic object model.
- [Generic range/set utilities](../../../../../base/nostd/) — range and string set infrastructure.
- `test/testcase/asn.1/` — source-level constraint construction and parser/publisher cases; inspect individual assertions for exact coverage.

### Implementation source navigation

- `asn1_constraint.hpp` and concrete `asn1_constraint_*.hpp` nodes
- `asn1_constraint_evaluator.hpp/.cpp`
- `sdk/base/nostd/set_runtime.hpp`, `range_set.hpp`, `string_set.hpp`
