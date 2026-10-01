# ASN.1 Constraints

## Role

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

## Constraint model

The implementation is organized around `asn1_constraint`.

A constraint can represent the restriction associated with an ASN.1 type rather than being treated as a property of one particular encoded value.

This lets the same constraint definition participate in:

- schema representation
- ASN.1 notation generation
- runtime validation
- constraint composition

The semantic ASN.1 object owns/associates its constraints, so a type and its restrictions remain together.

## Constraint categories

The constraint implementation covers the major forms needed by the ASN.1 subtype notation used by the project, including:

- value/range restrictions
- SIZE constraints
- permitted alphabet restrictions
- single-value / value-set style constraints
- intersection/union-style combinations
- extensibility-related constraint forms

The exact class hierarchy should be read from the implementation when extending the supported grammar; the important architectural point is that constraints are represented as objects and traversed by the visitor/evaluator layer.

## Notation versus semantic representation

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

## Evaluation

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

The evaluator is therefore the semantic bridge from ASN.1 constraint nodes to a concrete allowed-value domain; it is not part of DER encoding itself.

## Visitor relationship

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

## Relationship with the ASN.1 object model

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

## Tests

The main constraint-oriented test entry point is:

- `test/testcase/asn.1/testcase_constraints.cpp`

The test follows the same semantic construction path used by the other ASN.1 runtime experiments rather than testing notation parsing in isolation.

Related ASN.1 tests include:

- `testcase_basic2.cpp`
- `testcase_basic3.cpp`
- DER test vectors under `test/testcase/asn.1/`

## Related source

- `sdk/io/asn.1/basic/semantic/constraints/`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_visitor.*`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_notation_visitor.*`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.*`
- `sdk/io/asn.1/basic/semantic/asn1_object.*`

## Related documents

- `subtype-notation.md` — ASN.1 subtype notation study/reference
- `../../../../base/nostd/set.md` — runtime set façade used by constraint evaluation
- `../../../../base/nostd/range_set.md` — numeric/ordered constraint domain
- `../../../../base/nostd/string_set.md` — string constraint domain
- `../../asn1-object-model.md` — semantic ASN.1 object model
- `../../asn1-visitor.md` — general visitor architecture
- `../../../runtime/` — runtime schema/value processing

## Current status

The constraint layer is an implemented part of the semantic ASN.1 model, while the exact set of supported constraint forms should be determined from the current parser, semantic classes, and tests.

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
