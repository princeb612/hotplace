## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1132                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Built-in Types

## 1. Role

`basic/semantic/builtin` contains concrete implementations for ASN.1 primitive semantic types. The shared declarations in `types.hpp` include BOOLEAN, OCTET STRING, NULL, OBJECT IDENTIFIER, REAL, UTF8String, RELATIVE-OID, NumericString, PrintableString, TeletexString, VideotexString, IA5String, UTCTime, GeneralizedTime, GraphicString, VisibleString, GeneralString, UniversalString, and the internal C-string entity. INTEGER and BIT STRING have dedicated classes in `asn1_integer.*` and `asn1_bitstring.*`; ENUMERATED is implemented separately by `asn1_enum.*`.

These classes derive from the common `asn1_builtin_type` / `asn1_type` hierarchy. The directory is part of the larger semantic model in `../`, not a separate parser, DER decoder, or runtime subsystem.

## 2. Data Model
`asn1_builtin_type` stores the entity/name/default-value relationship and provides common notation and binary representation. Its binary writer selects the identifier from the semantic object, delegates value encoding to `asn1_value`, and handles the sequence-of/set-of visitor cases. Type-specific classes primarily select the ASN.1 entity and, where needed, add named-number or named-bit-list behavior. INTEGER, BIT STRING, and ENUMERATED maintain their own name/value mappings.

## 3. Behavior Model
A built-in type carries type-specific value/constraint behavior used by the broader semantic model. Its representation should remain consistent with the tag and encoding rule selected by the surrounding ASN.1 type/object path; a primitive class existing in source is not proof that every X.680 built-in type is implemented.

### Source-level evidence
`test/testcase/asn.1/testcase_basic1.cpp` contains table-driven primitive value/DER cases, including BOOLEAN, INTEGER, and REAL, plus direct generic built-in-object cases. `testcase_basic2.cpp` exercises semantic construction and selected round trips involving VisibleString, BOOLEAN, REAL, INTEGER, BIT STRING, ENUMERATED, and constructed types. `testcase_basic3.cpp` exercises schema-guided decoding for selected schemas. These are selected test cases: the presence of a concrete class in `types.hpp` does not mean that each primitive has an equivalent dedicated positive/negative test matrix or full X.680/X.690 conformance coverage.

### Practical example: follow an INTEGER constraint into evaluation

`test/testcase/asn.1/testcase_constraints.cpp` builds an INTEGER type, attaches a single-value constraint, and composes a union/range constraint before checking the runtime result. The caller-facing path is:

```text
asn1_builder::build(asn1_entity_integer, configure_constraints)
  -> builtin ASN.1 object with attached constraints
  -> asn1_constraint_evaluator<T>
  -> runtime allowed-value set / validation result
```

This is a useful way to study the built-in type boundary: the primitive supplies the value domain, while constraint objects describe permitted values and the evaluator interprets those constraints. The testcase demonstrates selected INTEGER and string constraint cases; it is not a per-primitive conformance suite and does not establish that every ASN.1 built-in type or X.680/X.690 rule is implemented.

## 4. Relationships
### Related areas

- `../` — ASN.1 semantic type hierarchy
- `../constraints/` — constraints applied to semantic types
- `../../` — structural and visitor layers
- `../../../runtime/` — runtime ASN.1 representation

### Related implementation and verification sources
- Built-in type sources under this directory, including INTEGER and BIT STRING implementations
- `../README.md` — ASN.1 semantic model
- `../../../../../../test/testcase/asn.1/`
- `../../../../../../test/testcase/asn.1/runtime/`
