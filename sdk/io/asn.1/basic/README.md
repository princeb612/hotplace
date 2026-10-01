# ASN.1 Basic

`asn.1/basic` contains the basic ASN.1 model and the study material used to understand how ASN.1 notation, tagging, encoding, constraints, and structural nodes map into hotplace.

## Detailed documents

- [ITU-T X.680](itu-t_x680.md) — notation and grammar study
- [Prefixed type encoding](prefixed-type-encoding.md) — X.690 8.14, IMPLICIT/EXPLICIT tagging, and encoding experiments
- [Structural representation](structural/structural.md) — ASN.1 structural node model
- [Subtype notation](semantic/constraints/subtype-notation.md) — subtype notation and value sets

## Implementation records

- [ASN.1 object model](asn1-object-model.md)
- [ASN.1 structural node model](asn1-node.md)
- [ASN.1 visitor architecture](asn1-visitor.md)
- [ASN.1 semantic constraints](semantic/constraints/asn1_constraints.md)

- `semantic/` — semantic type/object hierarchy
- `structural/` — structural node hierarchy
- `visitor/` — traversal and interpretation visitors

## Related areas

- `../runtime/` — runtime ASN.1 types and objects
- `../../parser/` — parser implementation used to construct ASN.1 syntax structures

## Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`

## Source

The implementation is centered on the ASN.1 basic type, tag, constraint, container, and structural-node classes under this directory.
