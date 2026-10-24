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
# ASN.1 Semantic Model

## 1. Role

`basic/semantic` contains the semantic ASN.1 type/object hierarchy used after syntax has been interpreted: built-in types, constructed types, tags, references, containers, parameterized prototypes, and constraints.

The semantic layer is distinct from `structural/`: semantic objects describe ASN.1 types and their relationships, while structural nodes describe concrete parsed/decoded structure. This directory does not own the generic lexer/grammar engine or the module registry that resolves names across ASN.1 modules.

## 2. Data Model

### Main implementation areas

| Area | Principal model | Responsibility |
|---|---|---|
| Common semantic model | `asn1_object`, `asn1_type` | Shared identity, parent/inner-object relationships, tags, optional/default flags and constraints |
| Built-in types | `builtin/`, `asn1_builtin_type` | Primitive ASN.1 type/value representations and their encoding behavior |
| Constructed types | `asn1_sequence`, `asn1_set`, `asn1_choice`, `asn1_container` | Named components and alternative/component structure |
| Collection types | `asn1_sequence_of`, `asn1_set_of`, `asn1_container_of` | Repeated element forms |
| Tagging | `asn1_tag`, `asn1_tagged_type` | Tag class/number and IMPLICIT/EXPLICIT interpretation |
| Named references | `asn1_referenced_type` | Definition versus reference state; linkage is separate from module-level lookup |
| Constraints | `constraints/` | Semantic restriction nodes and evaluation into a permitted value domain |
| Parameterized prototypes | `parameterized/` | Direct semantic definition/specialization model; not proof of complete end-to-end parser support |

### Common object and value relationship

`asn1_object` represents schema/type meaning. `asn1_value` is a separate value container associated with a schema object; it can hold named `variant` values and repeated components without making the schema itself the value container.

A referenced type can also be in one of two meaningful states:

- A **definition**, created with `define(name, object/entity)`, carries the semantic object that defines the type.
- A **reference**, created with `refer(name, reference)`, names a definition that must be resolved through module/runtime lookup.

`update_linkage()` propagates structural/tagging relationships through semantic objects; it is not a replacement for resolving a named reference against a module registry.

## 3. Behavior Model

### From syntax or direct construction to semantic objects

```text
ASN.1 notation
     |
     v
generic lexer / grammar parser
     |
     v
parse_tree
     |
     v
asn1_publisher handlers
     |
     +----> semantic type/object graph
     |             |
     |             +----> tag and inner-object linkage
     |             +----> DEFAULT / OPTIONAL state
     |             `----> constraint objects
     |
     `----> module publication and later name resolution
```

The semantic objects may also be assembled directly by client code or tests. In either case, the model's behavior depends on keeping schema identity, nested objects, tag behavior, optional/default state, and constraints attached to the correct semantic object.

### Boundaries that should not be conflated

- **Syntax recognition vs semantic construction:** a grammar production can recognize notation without the publisher constructing every corresponding semantic form.
- **Semantic linkage vs module resolution:** parent/inner-object linkage propagates local structure; resolving a reference name requires the module/runtime lookup path.
- **Constraint representation vs evaluation:** constraint nodes describe restrictions; the evaluator converts supported forms into a runtime set/value domain.
- **Parameterized prototype vs integrated support:** `parameterized/` contains a direct semantic prototype and specialization path, but the integrated parser/loader/publisher path is not complete.
- **Schema vs encoded structure:** semantic types express declared meaning; structural TLV nodes preserve the wire-level shape.

### Source-level evidence

- `test/testcase/asn.1/testcase_basic3.cpp` — direct semantic definitions/references and linkage-oriented cases.
- `test/testcase/asn.1/runtime/` — parser and publisher cases that connect notation processing to semantic reconstruction.
- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp` — direct parameterized-model tests and the separately bounded integration probe.

These paths indicate which behavior the source tests address; they are not a blanket claim of full X.680 conformance or complete end-to-end support for every grammar family.

## 4. Relationships
- [ASN.1 object model](../asn1-object-model.md) — common object, type/reference and value relationships.
- [Structural representation](../structural/README.md) — wire-level TLV structure versus semantic schema.
- [Constraints](constraints/README.md) — constraint nodes and runtime set evaluation.
- [Parameterized semantic prototype](parameterized/README.md) — direct definition/specialization and integration boundary.
- [Subtype notation](constraints/subtype-notation.md) — retained study note, distinct from implemented evaluator coverage.
- [Generic parser](../../../parser/README.md) — lexical/grammar parsing and parse-tree construction.
- [ASN.1 publisher](../../runtime/asn1_publisher.md) — semantic reconstruction from the parse tree.

### Implementation source navigation

- `asn1_object.hpp`, `asn1_type.hpp`, `asn1_referenced_type.hpp`
- `asn1_sequence.hpp`, `asn1_set.hpp`, `asn1_choice.hpp`, `asn1_container.hpp`
- `asn1_tag.hpp`, `asn1_tagged_type.hpp`, `asn1_value.hpp`
- `constraints/`, `parameterized/`, `builtin/`
