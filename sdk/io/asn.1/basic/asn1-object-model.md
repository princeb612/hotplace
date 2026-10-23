## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Object Model

## 1. Role

The semantic layer under `sdk/io/asn.1/basic/semantic` is the main in-memory representation of ASN.1 types and values used by the runtime, visitors, constraints, and DER encoding paths.

The semantic model contains the ASN.1 type families used by the runtime: built-in types, constructed types, tagging, references, constraints, object classes, and container forms.

## 2. Data Model
### Central abstraction: `asn1_object`

`asn1_object` is the common base of the semantic model.

It carries:

- ASN.1 entity/type identity
- name and parent relationship
- optional tag information
- primitive/constructed state
- DEFAULT / OPTIONAL state
- IMPLICIT / EXPLICIT suppression state
- constraints
- an optional inner object for wrapped/tagged/reference structures

The object also provides the common operations used by visitors and runtime code:

```text
schema object
 ├─ identify entity
 ├─ carry tag
 ├─ carry constraints
 ├─ carry parent/child linkage
 ├─ represent as notation
 └─ represent/encode as DER
```

`update_linkage()` is important for constructed/tagged structures because linkage information is propagated through the object hierarchy.

### Type families

The semantic implementation contains several major families.

### Built-in types

The `semantic/builtin` area contains primitive ASN.1 types such as:

- INTEGER
- BIT STRING
- and the common built-in type machinery

These types connect ASN.1 entities to the `variant_t`-based value layer and DER encoding.

### Constructed types

Constructed schema objects include:

- `asn1_sequence`
- `asn1_set`
- `asn1_choice`
- `asn1_sequence_of`
- `asn1_set_of`
- container forms

They model named components and repeated/alternative components while retaining ASN.1 tagging and optional/default semantics.

### Tagged types

`asn1_tagged_type` wraps another object with ASN.1 class/tag information and models IMPLICIT/EXPLICIT tagging.

The underlying object is retained rather than flattened, which is important when resolving and encoding nested tagged definitions.

### Referenced types

`asn1_referenced_type` represents both definitions and references.

```text
Type1 ::= VisibleString
Type2 ::= [Application 3] IMPLICIT Type1
```

The API distinguishes:

- `define(name, object/entity)` — create a named definition
- `refer(name, reference)` — create a named reference
- `is_definition()`
- `is_reference()`
- `get_reference()`

This is a key bridge between notation-derived definitions and runtime schema lookup.

### Values

`asn1_value` is separate from the schema object.

```text
asn1_object
    = schema / type description

asn1_value
    = values associated with that schema
```

An `asn1_value` keeps a schema pointer and a multimap of named `variant` values. It can therefore represent named components and repeated values without making the schema object itself the value container.

### Visitors and encoding

The semantic objects are consumed by visitor implementations:

- AST/semantic traversal
- ASN.1 notation representation
- DER encoding
- constraint evaluation

The same object model therefore serves both the human-readable ASN.1 representation and binary encoding paths.

## 3. Behavior Model

### Constructing and linking a type

A semantic type can be created directly or reconstructed by publisher handlers from a parse tree. The important stages are definition/reference creation, attachment of child or inner objects, and linkage propagation for structures whose meaning depends on nested tagged or referenced types.

```text
parse_tree / direct model construction
              |
              v
       semantic type object
              |
       +------+------+
       |             |
       v             v
   tag / inner    reference name
     object           |
       |              v
       |         module lookup
       |              |
       +-------+------+
               v
        update_linkage()
               |
               v
       linked semantic model
               |
       +-------+--------+
       |                |
       v                v
 notation visitor   DER visitor
```

For referenced types, `define(name, object/entity)` creates a definition and `refer(name, reference)` records a reference. These are distinct states: the reference must still be resolved through runtime/module lookup, and linkage propagation is not a substitute for name resolution.

### Schema and value are separate

`asn1_object` describes a schema/type; `asn1_value` carries values associated with that schema. The value representation uses the schema pointer plus named variant values, so repeated or named components do not turn the schema object itself into the value store.

### Constraints and output operations

Constraints remain attached to the semantic type model. Visitors then perform distinct operations over that model: notation representation, DER representation, AST traversal, or constraint evaluation. Constraint evaluation derives an allowed value domain; it is not the same operation as encoding the object.

### Related tests

- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/asn.1/runtime/`

These are source-level examples of semantic model behavior; this documentation update did not execute them.

## 5. Relationships
### Runtime relationship

The current high-level relationship is:

```text
ASN.1 notation
      |
      v
parser
      |
      v
semantic ASN.1 objects
      |
      +------------------+
      |                  |
      v                  v
asn1_module        visitors / DER
      |
      v
asn1_value / strongly typed use
```

The semantic layer is consequently the central model between parsing and runtime use.

### Implementation source navigation
- `sdk/io/asn.1/basic/semantic/asn1_object.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_type.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_sequence.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_choice.hpp`
- `sdk/io/asn.1/basic/semantic/builtin/`
- `sdk/io/asn.1/basic/semantic/constraints/`
- `sdk/io/asn.1/basic/asn1_value.hpp`
