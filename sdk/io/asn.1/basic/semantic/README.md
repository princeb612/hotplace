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
# ASN.1 Semantic Model

## 1. Role

`basic/semantic` contains the semantic ASN.1 type/object hierarchy used after syntax has been interpreted: built-in types, constructed types, tags, references, containers, and constraints.

The semantic layer is distinct from `structural/`: semantic objects describe ASN.1 types and their relationships, while structural nodes describe concrete parsed/decoded structure.

## 2. Data Model
### Main implementation areas

- `asn1_object` / `asn1_type` — common semantic object/type model
- `asn1_builtin_type` and built-in types — primitive ASN.1 type families
- `asn1_sequence`, `asn1_set`, `asn1_choice`, `asn1_container` — constructed types
- `asn1_sequence_of`, `asn1_set_of`, `asn1_container_of` — collection forms
- `asn1_tag`, `asn1_tagged_type` — tagging
- `asn1_referenced_type` — references and definitions
- `parameterized/` — parameter/type/value descriptors and direct semantic prototypes for parameterized ASN.1
- `constraints/` — subtype/value constraints
- `builtin/` — concrete built-in value/type implementations

## 3. Behavior Model
The semantic model describes ASN.1 type/value relationships rather than the exact syntax tree. Constructed types own or reference child type definitions; references distinguish a named definition from a reference to that definition; tags and constraints alter interpretation/encoding behavior. Constraint and parameterized-type submodules have their own implementation boundaries.

Do not collapse semantic types into structural nodes: the semantic model is used to understand what a notation element means, while structural nodes preserve parsed/decoded structure for traversal and publication.

### Source-level evidence
`test/testcase/asn.1/testcase_basic3.cpp` and the runtime testcase directory contain source-level examples of ASN.1 definitions and references. A useful tracing point is the distinction between a referenced type that names another definition and a definition object that carries the actual semantic type. Follow the individual assertions before claiming full parser-to-runtime coverage.

## 4. Relationships
### Related documents

- `../asn1-object-model.md` — semantic object model overview
- `constraints/README.md` — constraint subsystem
- `parameterized/README.md` — parameterized semantic model and current implementation boundary
- `constraints/subtype-notation.md` — ASN.1 subtype notation study

### Related implementation and verification sources
- `asn1_object.hpp`, `asn1_type.hpp`, `asn1_referenced_type.hpp`
- `asn1_sequence.hpp`, `asn1_set.hpp`, `asn1_choice.hpp`, `asn1_container.hpp`
- `constraints/`, `parameterized/`, `builtin/`
- [ASN.1 object model](../asn1-object-model.md)
- `test/testcase/asn.1/`
