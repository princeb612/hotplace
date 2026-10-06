# ASN.1 Constraint → Set Model

> **Review baseline:** Revision 1097

## Review thesis

**The important architectural step is that ASN.1 constraint semantics are expressed through a reusable set model instead of remaining embedded inside the ASN.1 parser or ASN.1-specific constraint classes.**

## Architectural view

```text
ASN.1 constraint tree
        ↓
asn1_constraint_evaluator<T>
        ↓
t_set_runtime<T>
   ┌────┴────┐
   ↓         ↓
string_set  t_range_set<t_range_value<T>>
   │         │
   └────┬────┘
        ↓
UNION / INTERSECT / EXCEPT / ALL EXCEPT
        ↓
open / closed boundaries
```

The model treats a constraint as a **set of values that are allowed by the constraint**. That changes the implementation problem from “evaluate every ASN.1 constraint form separately” into a composition of set operations.

A value constraint can be inserted as a member. A range becomes a range insertion. UNION and INTERSECTION become set composition, while EXCEPT removes values or ranges from an existing result. ALL EXCEPT is represented by the corresponding inverted set semantics. Boundary information remains part of the range representation rather than being reimplemented by each ASN.1 constraint operator.

This gives the evaluator a stable semantic target: the ASN.1 syntax describes the constraint, while the set model represents the resulting value domain.

## Why the separation matters

The architectural boundary is not the directory boundary between `sdk/io/asn.1` and `sdk/base/nostd`. The meaningful boundary is between **ASN.1 constraint semantics** and the **generic representation of a set of permitted values**.

That separation has three useful consequences:

1. **ASN.1 semantics become compositional.** The evaluator can map different constraint forms onto a small set of operations instead of creating a separate execution mechanism for every grammar form.
2. **The value-domain representation is reusable.** `range_set` and `string_set` do not need to know that their inputs originated in ASN.1. The same abstraction can represent other interval- or membership-oriented problems.
3. **Parser and runtime concerns remain separate.** Parsing identifies constraint structure; semantic evaluation turns that structure into a value-domain representation. The set implementation does not become part of the ASN.1 grammar machinery.

## Generic set model

The runtime layer selects the representation according to the value type:

```text
                    t_set_runtime<T>
                         │
              ┌──────────┴──────────┐
              │                     │
       T == std::string        other value types
              │                     │
         string_set          t_range_set<...>
```

This is important because string constraints and numeric/range constraints have different natural representations, while their higher-level role is the same: **describe the permitted value domain**.

## Relationship to ASN.1 constraints

The model is particularly useful for the compound constraint forms already represented by the ASN.1 semantic layer:

```text
Constraint
  ↓
ConstraintSpec
  ↓
SubtypeElementSetSpec
  ├── UNION
  ├── INTERSECT
  ├── EXCEPT
  └── ALL EXCEPT
        ↓
  SubtypeElement / PrimaryElement
        ├── value
        ├── range
        ├── SIZE
        ├── FROM
        └── PATTERN
```

The review point is therefore not that `range_set` happens to be used by ASN.1. It is that **a syntactic constraint tree has been given a domain-level semantic representation that can be manipulated independently of the syntax that produced it**.

## Reuse beyond ASN.1

This abstraction also explains why the same range machinery is relevant to other protocol work, including QUIC ACK ranges. The semantics are not identical—an ACK range is not an ASN.1 constraint—but both problems need reliable representation and manipulation of ordered ranges and their boundaries.

That reuse is evidence of a useful abstraction boundary: the generic range operation is valuable independently of the protocol that happens to consume it.

## Strengths

- Constraint evaluation is expressed as composition rather than a collection of unrelated special cases.
- Range boundaries have one representation and one set of operations.
- String and non-string domains can share the same semantic role while using different concrete representations.
- The ASN.1 evaluator remains responsible for ASN.1 meaning instead of leaking protocol-specific assumptions into the generic set implementation.
- The resulting abstraction is useful outside the original ASN.1 problem.

## Costs and limitations

The separation also introduces another abstraction layer. A reader must understand both ASN.1 constraint semantics and the generic set model before the implementation becomes obvious. The generic set representation also cannot by itself define ASN.1 semantics; the evaluator still has to translate ASN.1-specific constructs such as `SIZE`, `FROM`, `PATTERN`, and `ALL EXCEPT` into the appropriate domain operations.

The model should therefore not be interpreted as a claim that all ASN.1 constraint handling has become generic. It is a semantic representation layer underneath the ASN.1-specific evaluator.

## Current state

At revision 1097, the important result is the established relationship between the ASN.1 constraint evaluator and the reusable set infrastructure. The relevant tests cover the generic set behavior and ASN.1 constraint evaluation separately, making the abstraction boundary visible in the test structure as well.

### Related source / documents

- `sdk/base/nostd/range_set.hpp`
- `sdk/base/nostd/set.hpp`
- `sdk/base/nostd/range.hpp`
- ASN.1 semantic constraint classes
- `test/testcase/base/nostd/testcase_set.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `sdk/base/nostd/README.md`
- `sdk/io/asn.1/basic/semantic/constraints/README.md`
- `sdk/io/asn.1/basic/semantic/constraints/asn1-constraints.md`

---

**GPT Review**

Reviewed against the hotplace source/documentation state around **revision 1097**.
