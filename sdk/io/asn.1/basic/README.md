## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Basic

## 1. Role

`asn.1/basic` contains the basic ASN.1 model and the study material used to understand how ASN.1 notation, tagging, encoding, constraints, and structural nodes map into hotplace.

## 2. Model

### Detailed documents

- [ITU-T X.680](itu-t_x680.md) — notation and grammar study
- [Prefixed type encoding](prefixed-type-encoding.md) — X.690 8.14, IMPLICIT/EXPLICIT tagging, and encoding experiments
- [Structural representation](structural/structural.md) — ASN.1 structural node model
- [Subtype notation](semantic/constraints/subtype-notation.md) — subtype notation and value sets

### Implementation records

- [ASN.1 object model](asn1-object-model.md)
- [ASN.1 structural node model](asn1-node.md)
- [ASN.1 visitor architecture](asn1-visitor.md)
- [ASN.1 semantic constraints](semantic/constraints/asn1_constraints.md)

- `semantic/` — semantic type/object hierarchy
- `structural/` — structural node hierarchy
- `visitor/` — traversal and interpretation visitors

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`

## 5. Relationships

### Related areas

- `../runtime/` — runtime ASN.1 types and objects
- `../../parser/` — parser implementation used to construct ASN.1 syntax structures

## 6. References

### Source

The implementation is centered on the ASN.1 basic type, tag, constraint, container, and structural-node classes under this directory.
