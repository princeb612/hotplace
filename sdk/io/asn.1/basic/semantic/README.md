# ASN.1 Semantic Model

`basic/semantic` contains the semantic ASN.1 type/object hierarchy used after syntax has been interpreted: built-in types, constructed types, tags, references, containers, and constraints.

The semantic layer is distinct from `structural/`: semantic objects describe ASN.1 types and their relationships, while structural nodes describe concrete parsed/decoded structure.

## Main implementation areas

- `asn1_object` / `asn1_type` — common semantic object/type model
- `asn1_builtin_type` and built-in types — primitive ASN.1 type families
- `asn1_sequence`, `asn1_set`, `asn1_choice`, `asn1_container` — constructed types
- `asn1_sequence_of`, `asn1_set_of`, `asn1_container_of` — collection forms
- `asn1_tag`, `asn1_tagged_type` — tagging
- `asn1_referenced_type` — references and definitions
- `constraints/` — subtype/value constraints
- `builtin/` — concrete built-in value/type implementations

## Related documents

- `../asn1-object-model.md` — semantic object model overview
- `constraints/README.md` — constraint subsystem
- `constraints/subtype-notation.md` — ASN.1 subtype notation study
