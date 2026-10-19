## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Constraints

## 1. Role

The module identity is described by the implementation notes retained below.

## 2. Model

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

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/`

## 5. Relationships

### Related areas

- `../../` — ASN.1 basic type model
- `../../../runtime/` — runtime representation of ASN.1 types

## 6. References

Source references and related documents are retained below where available.
