## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Constraints

## 1. Role

The constraint implementation under `sdk/io/asn.1/basic/semantic/constraints` represents the semantic form of ASN.1 subtype/value constraints.

The important distinction is:

```text
ASN.1 constraint notation
        |
        v
constraint object
        |
        v
constraint traversal / evaluation
        |
        v
accept / reject a value
```

The constraint layer therefore sits between ASN.1 notation and runtime value validation.

At runtime, constraint evaluation is one part of validation, not a replacement for built-in type checks. In Revision 1132, `asn1_object::validate()` enters `validate_node()`, which first calls `validate_type()`. If the current node has constraints, validation returns the result of `asn1_constraints::validate()`; otherwise, container children are traversed recursively. This ordering matters: a successful constraint check on a node with attached constraints does not also imply that every child schema node was traversed.

ENUMERATED membership is handled through the constraints path even when the enum object has no explicit constraint nodes: `asn1_enum::have_constraints()` returns true, allowing `asn1_constraints::validate()` to run its enum-specific lookup. The value may be represented by its enumerator name or integer value, and the enum lookup rejects values that are not declared members. Successful notation reconstruction alone does not establish that property.

## 2. Data Model
### Constraint model

The implementation is organized around `asn1_constraint`.

A constraint can represent the restriction associated with an ASN.1 type rather than being treated as a property of one particular encoded value.

This lets the same constraint definition participate in:

- schema representation
- ASN.1 notation generation
- runtime validation
- constraint composition

The semantic ASN.1 object owns/associates its constraints, so a type and its restrictions remain together.

### Concrete constraint forms

The current implementation represents individual constraint forms as semantic nodes under `asn1_constraint`, rather than encoding every form directly into the evaluator. The source tree contains concrete nodes for: 

- `asn1_constraint_range` — ordered/range restrictions
- `asn1_constraint_single_value` — a single permitted value
- `asn1_constraint_size` — SIZE-derived restrictions
- `asn1_constraint_pattern` — pattern-based string restrictions
- `asn1_constraint_union` — union of constraint domains
- `asn1_constraint_intersection` — intersection of domains
- `asn1_constraint_except` — subtraction from a domain
- `asn1_constraint_all_except` — complement-style restriction
- `asn1_constraint_from` / related container forms — subtype/alphabet-style composition

The evaluator does not replace these nodes. Constraint classes describe the semantic operations; the evaluator's traversal and conversion into a value-domain representation are covered under Behavior Model.

### Constraint categories

The constraint implementation covers the major forms needed by the ASN.1 subtype notation used by the project, including:

- value/range restrictions
- SIZE constraints
- permitted alphabet restrictions
- single-value / value-set style constraints
- intersection/union-style combinations
- parser grammar contains extension-marker productions in the ASN.1 module/type path; those productions should not be conflated with runtime subtype-set evaluation.

The exact class hierarchy should be read from the implementation when extending the supported grammar; the important architectural point is that constraints are represented as objects and traversed by the visitor/evaluator layer.

## 3. Behavior Model
### Notation versus semantic representation

The existing `subtype-notation.md` is a study/reference document for ASN.1 subtype notation.

The implementation path is different:

```text
ASN.1 source

  INTEGER (0..100)
  SIZE (1..32)
  ...

        |
        v

parser / semantic construction

        |
        v

asn1_constraint
        |
        +---- notation visitor
        |
        +---- constraint visitor
        |
        +---- evaluator
```

This distinction is useful when maintaining the parser: changing the notation grammar does not automatically mean changing the evaluator, and vice versa.

### Evaluation

`asn1_constraint_evaluator` walks the semantic constraint tree and builds a runtime set describing the permitted value domain. A value can then be checked against that resulting set.

The important implementation path is:

```text
ASN.1 constraint tree
        |
        v
asn1_constraint_evaluator<T>
        |
        | get_result_set()
        v
 t_set_runtime<T>
        |
   +----+----+
   |         |
 numeric   string
   |         |
   v         v
range_set string_set
```

Constraint composition is also expressed as set algebra:

```text
UNION        → union_with()
INTERSECTION → intersect_with()
EXCEPT       → erase_from()
ALL EXCEPT   → invert()
```

The evaluator is therefore the semantic bridge from ASN.1 constraint nodes to a concrete allowed-value domain; it is not part of DER encoding itself. `asn1_constraints::validate()` dispatches integer/container, REAL, and string-like values to the corresponding evaluator specialization. For each attached constraint node, the validation result must succeed; a failing node rejects the value.

For SIZE constraints, the validator checks the number of elements for SEQUENCE OF / SET OF, the byte count for OCTET STRING (the stored hexadecimal representation is divided by two), and the stored character/bit count for other string-like values. String `FROM` constraints use the runtime set's alphabet check, `PATTERN` uses its regular-expression check, and other string constraints use membership.

### Evaluation implementation map

The current evaluator-to-set relationship is implemented as a concrete runtime chain:

```text
asn1_constraint
      │
      ▼
asn1_constraint_evaluator<T>
      │
      │ get_result_set()
      ▼
t_set_runtime<T>
      │
      ├── numeric / real → t_range_set<t_range_value<T>>
      └── std::string    → string_set
```

The evaluator performs semantic traversal of the constraint tree; `t_set_runtime` supplies the type-dependent representation. This separation lets the generic set implementation remain under `sdk/base/nostd` while the meaning of ASN.1 constraint nodes remains under `sdk/io/asn.1`.

### Current status

The constraint layer is an implemented part of the semantic ASN.1 model, while the exact set of supported constraint forms should be determined from the current parser, semantic classes, and tests. Revision 1132 source supports concrete range, single-value, SIZE, FROM, PATTERN, UNION, INTERSECTION, EXCEPT, and ALL EXCEPT nodes, with integer, REAL, and string-oriented runtime-set paths. This is not evidence of complete X.682 coverage.

The built-in type checks in `asn1_object::validate_type()` are also deliberately bounded: several string entities are checked only for string-valued storage, UTCTime/GeneralizedTime use shape-oriented regular expressions, and the default branch accepts entities such as SEQUENCE, SET, ENUMERATED and referenced types for further processing. These checks should not be described as complete ASN.1 semantic or character-encoding validation.

When new ASN.1 constraint syntax is added, the maintenance path is generally:

```text
grammar / parser
      |
semantic constraint construction
      |
constraint representation
      |
notation / evaluator visitor
      |
testcase
```

### Source-level evidence
### Tests

The main constraint-oriented test entry point is:

- `test/testcase/asn.1/testcase_constraints.cpp`

The test constructs its semantic constraint objects directly with `asn1_builder` and concrete `asn1_constraint_*` nodes. For each table entry, it separately calls `parse_notation()` on the expected notation; that helper records the parser status, but the parsed module is not used for the later `type->validate(value)` call. The source table checks notation output and selected positive/negative value cases for integer and REAL ranges, union/intersection/EXCEPT/ALL EXCEPT, SIZE on IA5String/OCTET STRING/BIT STRING/SEQUENCE OF/SET OF, permitted alphabets, ENUMERATED membership, nested SEQUENCE fields, PATTERN, and an exclusive range boundary. The BOOLEAN constraint examples are commented out and are not active test cases.

These are source-level cases, not a claim that the test executable was run during this audit. The test table is a selected sample, not exhaustive coverage of all constraint forms or value domains.

Related ASN.1 tests include:

- `testcase_basic2.cpp`
- `testcase_basic3.cpp`
- DER test vectors under `test/testcase/asn.1/`

## 4. Relationships
### Visitor relationship

Constraint traversal is separated from evaluation.

The relevant visitor family includes:

- `asn1_constraint_visitor`
- `asn1_constraint_notation_visitor`
- `asn1_constraint_evaluator`

This allows the same constraint tree to be used for both representation and execution.

```text
              constraint tree
                    |
          +---------+---------+
          |                   |
          v                   v
 notation visitor       evaluator
          |                   |
          v                   v
    ASN.1 notation      value validation
```

### Relationship with the ASN.1 object model

Constraints are not an isolated utility.

```text
asn1_object
 ├── type information
 ├── tag information
 ├── DEFAULT / OPTIONAL
 └── constraints
          |
          v
  asn1_constraint
          |
          v
  constraint evaluator
          |
          v
     asn1_value
```

This is why constraint handling belongs to the semantic model rather than only to the parser.

### Related documents

- `subtype-notation.md` — ASN.1 subtype notation study/reference
- `../../../../base/nostd/set.md` — runtime set façade used by constraint evaluation
- `../../../../base/nostd/range_set.md` — numeric/ordered constraint domain
- `../../../../base/nostd/string_set.md` — string constraint domain
- `../../asn1-object-model.md` — semantic ASN.1 object model
- `../../asn1-visitor.md` — general visitor architecture
- `../../../runtime/` — runtime schema/value processing

### Related implementation sources
- `sdk/io/asn.1/basic/semantic/constraints/`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_visitor.*`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_notation_visitor.*`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.*`
- `sdk/io/asn.1/basic/semantic/asn1_object.*`
