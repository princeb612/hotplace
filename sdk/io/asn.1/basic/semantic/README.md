## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Semantic Model

## 1. Role

`basic/semantic` contains the semantic ASN.1 type/object hierarchy used after syntax has been interpreted: built-in types, constructed types, tags, references, containers, and constraints.

The semantic layer is distinct from `structural/`: semantic objects describe ASN.1 types and their relationships, while structural nodes describe concrete parsed/decoded structure.

## 2. Model

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

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

### Related documents

- `../asn1-object-model.md` — semantic object model overview
- `constraints/README.md` — constraint subsystem
- `parameterized/README.md` — parameterized semantic model and current implementation boundary
- `constraints/subtype-notation.md` — ASN.1 subtype notation study

## 6. References

Source references and related documents are retained below where available.
