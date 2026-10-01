# ASN.1 Visitor

## Role

The visitor layer provides operations over ASN.1 semantic/structural objects without embedding every traversal or representation operation into the node classes themselves.

At revision 1095 the visitor family includes:

- `asn1_visitor`
- `asn1_ast_visitor`
- `asn1_notation_visitor`
- `asn1_der_visitor`
- `asn1_constraint_visitor`
- `asn1_constraint_notation_visitor`
- `asn1_constraint_evaluator`

## Main visitor paths

The visitors serve different interpretations of the same ASN.1 model.

```text
                  ASN.1 objects
                       |
          +------------+------------+
          |            |            |
          v            v            v
       notation       DER       constraints
          |            |            |
          v            v            v
   human-readable    binary      evaluation
```

### AST visitor

`asn1_ast_visitor` provides traversal-oriented access to ASN.1 object structures.

### Notation visitor

`asn1_notation_visitor` converts semantic ASN.1 objects back toward ASN.1 notation-style representation.

This is useful for inspecting or publishing the schema representation.

### DER visitor

`asn1_der_visitor` drives DER representation/encoding from the ASN.1 object model.

It is one of the links between the semantic model and the binary encoding implementation.

### Constraint visitors

The constraint visitor family separates traversal from constraint-specific operations.

- `asn1_constraint_visitor` — common constraint traversal interface
- `asn1_constraint_notation_visitor` — notation representation of constraints
- `asn1_constraint_evaluator` — evaluates constraints into a runtime allowed-value set and supports value membership through that result

## Design significance

The visitor layer keeps operations such as:

```text
walk schema
render notation
encode DER
evaluate constraints
```

outside the core semantic object classes.

That matters because the same `asn1_object` hierarchy is used by runtime construction, schema inspection, encoding, and validation.

## Related source

- `sdk/io/asn.1/basic/visitor/asn1_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_ast_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.hpp`

## Related areas

- `../semantic/` — semantic object hierarchy
- `../structural/` — structural node hierarchy
- `../../runtime/` — runtime schema/value handling
- `../../parser/` — parsed ASN.1 representation

## Related tests

- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/asn.1/testvector_der.cpp`
