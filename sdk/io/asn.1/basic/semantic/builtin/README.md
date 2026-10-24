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
# ASN.1 Built-in Types

## 1. Role

`basic/semantic/builtin` contains concrete implementations for selected ASN.1 built-in primitive types.

The directory currently contains focused implementations such as INTEGER and BIT STRING. They are part of the larger semantic model in `../` rather than a separate encoding/runtime subsystem.

## 2. Data Model
The directory contains concrete built-in semantic types such as INTEGER and BIT STRING. They plug into the common `asn1_builtin_type` hierarchy rather than defining a separate parser or encoder pipeline.

## 3. Behavior Model
A built-in type carries type-specific value/constraint behavior used by the broader semantic model. Its representation should remain consistent with the tag and encoding rule selected by the surrounding ASN.1 type/object path; a primitive class existing in source is not proof that every X.680 built-in type is implemented.

### Source-level evidence
The current `test/testcase/asn.1/` and `test/testcase/asn.1/runtime/` suites are the starting points for built-in type behavior. No dedicated per-type testcase inventory is recorded in this README, so coverage for a specific primitive should be confirmed from the concrete testcase functions and assertions.

### Practical example: follow an INTEGER constraint into evaluation

`test/testcase/asn.1/testcase_constraints.cpp` builds an INTEGER type, attaches a single-value constraint, and composes a union/range constraint before checking the runtime result. The caller-facing path is:

```text
asn1_builder::build(asn1_entity_integer, configure_constraints)
  -> builtin ASN.1 object with attached constraints
  -> asn1_constraint_evaluator<T>
  -> runtime allowed-value set / validation result
```

This is a useful way to study the built-in type boundary: the primitive supplies the value domain, while constraint objects describe permitted values and the evaluator interprets those constraints. The testcase demonstrates selected INTEGER/string cases; it is not evidence that every ASN.1 built-in type or X.680 rule is implemented.

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
