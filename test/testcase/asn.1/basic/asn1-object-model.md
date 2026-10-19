## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ASN.1 object-model testcase notes

## 1. Role

This document describes the ASN.1 object hierarchy and the testcase surface used to exercise object construction, references, values, constraints, visitors, and encoding.

## 2. Test model

The original object-model explanation is retained below, including built-in, constructed, tagged, and referenced type families, values, constraints, visitor/encoding paths, and runtime relationships.

### Preserved source material

### Role

The semantic layer under `sdk/io/asn.1/basic/semantic` is the main in-memory representation of ASN.1 types and values used by the runtime, visitors, constraints, and DER encoding paths.

At revision 1095 it contains the bulk of the ASN.1 type model: built-in types, constructed types, tagging, references, constraints, object classes, and container forms.

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

#### Built-in types

The `semantic/builtin` area contains primitive ASN.1 types such as:

- INTEGER
- BIT STRING
- and the common built-in type machinery

These types connect ASN.1 entities to the `variant_t`-based value layer and DER encoding.

#### Constructed types

Constructed schema objects include:

- `asn1_sequence`
- `asn1_set`
- `asn1_choice`
- `asn1_sequence_of`
- `asn1_set_of`
- container forms

They model named components and repeated/alternative components while retaining ASN.1 tagging and optional/default semantics.

#### Tagged types

`asn1_tagged_type` wraps another object with ASN.1 class/tag information and models IMPLICIT/EXPLICIT tagging.

The underlying object is retained rather than flattened, which is important when resolving and encoding nested tagged definitions.

#### Referenced types

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

### Constraints

Constraints are owned by `asn1_object` and exposed through `asn1_constraints`.

The semantic model therefore carries both:

```text
ASN.1 type
   +
tagging
   +
DEFAULT / OPTIONAL
   +
constraints
```

rather than treating constraints as a separate post-processing feature.

### Visitors and encoding

The semantic objects are consumed by visitor implementations:

- AST/semantic traversal
- ASN.1 notation representation
- DER encoding
- constraint evaluation

The same object model therefore serves both the human-readable ASN.1 representation and binary encoding paths.

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

### Related source

- `sdk/io/asn.1/basic/semantic/asn1_object.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_type.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_sequence.hpp`
- `sdk/io/asn.1/basic/semantic/asn1_choice.hpp`
- `sdk/io/asn.1/basic/semantic/builtin/`
- `sdk/io/asn.1/basic/semantic/constraints/`
- `sdk/io/asn.1/basic/asn1_value.hpp`

### Related tests

- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/asn.1/runtime/`

These tests demonstrate the transition from manually constructed/parsed schema objects to runtime values and strongly typed use.

## 3. Example: source-specific testcase path

`testcase_basic2.cpp` uses a `Person ::= SEQUENCE { name VisibleString, age INTEGER DEFAULT 20 }` schema and the `asn1_referenced_type::define(...)` / reference APIs. `testcase_basic1.cpp` contains X.690 identifier and length byte vectors.

## 4. Test and verification status

### 4.1 Source-level coverage

- **O** — explicit byte comparisons and invalid DER identifier vectors are present in `testcase_basic1.cpp`.
- **O** — the basic object-model sources cover construction and relationships.
- **△** — documentation of a type family does not by itself show each edge case has a dedicated assertion.

### 4.2 Documentation and verification status

The suite-level ASN.1 report records pass 1628, expt 40, fail 0, skip 0, triv 0. It does not provide per-function execution evidence or environment/revision metadata.

## 5. Relationships

- [`../../README.md`](../README.md) — suite overview
- [`../../runtime/asn1_module.md`](../runtime/asn1_module.md) — module/reference resolution
- [`../../../../sdk/io/asn.1/basic/asn1-object-model.md`](../../../../sdk/io/asn.1/basic/asn1-object-model.md) — implementation-side model

## 6. References

- `test/testcase/asn.1/testcase_basic1.cpp`
- `test/testcase/asn.1/testcase_basic2.cpp`
- `sdk/io/asn.1/basic/`
