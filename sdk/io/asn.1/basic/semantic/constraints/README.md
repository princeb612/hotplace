## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Constraints

## 1. Role

`basic/semantic/constraints` contains the ASN.1 subtype/constraint model and evaluator path used to represent and check value-set/range restrictions. It bridges ASN.1 semantic constraints to generic runtime sets in `sdk/base/nostd`.

## 2. Data Model
### Documents

- [ASN.1 constraints](asn1_constraints.md) — implementation record
- [Subtype notation and value sets](subtype-notation.md) — study/reference

### Runtime set backend

Constraint evaluation ultimately uses the generic set infrastructure under `sdk/base/nostd`:

```text
asn1_constraint_evaluator<T>
          │
          ▼
    t_set_runtime<T>
       ┌──┴───┐
       ▼      ▼
 range_set string_set
```

See [asn1_constraints](asn1_constraints.md) for the semantic constraint layer and the evaluator path.

## 3. Behavior Model
The evaluator operates on semantic constraint information and delegates set operations to the generic runtime-set backend. Range and string constraints use different set representations; do not assume every constraint reduces to one numeric interval. Keep the notation/reference document separate from the implementation record: the standard's syntax and the subset handled by the current evaluator are different claims.


## 4. Relationships
### Related areas

- `../../` — ASN.1 basic type model
- `../../../runtime/` — runtime representation of ASN.1 types

### Related implementation and verification sources
- [ASN.1 constraints](asn1_constraints.md)
- [Subtype notation and value sets](subtype-notation.md)
- `sdk/base/nostd/range_set.hpp`, `string_set.hpp`, `set_runtime.hpp`
- `test/testcase/asn.1/`
