# ASN.1 Constraints

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


ASN.1 constraint support and the notation used to describe subtype/value-set restrictions.

## Documents

- [ASN.1 constraints](asn1_constraints.md) — implementation record
- [Subtype notation and value sets](subtype-notation.md) — study/reference

## Related areas

- `../../` — ASN.1 basic type model
- `../../../runtime/` — runtime representation of ASN.1 types

## Related tests

- `test/testcase/asn.1/`


## Runtime set backend

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
