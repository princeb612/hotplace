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
# ASN.1 Visitor

## 1. Role

The visitor layer provides operations over ASN.1 semantic/structural objects without embedding every traversal or representation operation into the node classes themselves.

The visitor family includes:

- `asn1_visitor`
- `asn1_ast_visitor`
- `asn1_notation_visitor`
- `asn1_der_visitor`
- `asn1_constraint_visitor`
- `asn1_constraint_notation_visitor`
- `asn1_constraint_evaluator`

## 2. Data Model
### Main visitor paths

The visitors serve different interpretations of the same ASN.1 model.

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

### Design significance

The visitor layer keeps operations such as:

```text
walk schema
render notation
encode DER
evaluate constraints
```

outside the core semantic object classes.

That matters because the same `asn1_object` hierarchy is used by runtime construction, schema inspection, encoding, and validation.

## 3. Behavior Model

### Operation dispatch

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


### Dispatch by requested operation

The visitor family shares the ASN.1 object model but has distinct output or evaluation paths. The selected operation determines how the model is traversed and what the traversal produces.

```text
asn1_object / constraint tree
             |
       visitor dispatch
             |
     +-------+---------+----------------+
     |                 |                |
     v                 v                v
notation visitor   DER visitor    constraint evaluator
     |                 |                |
     v                 v                v
ASN.1 text         DER bytes      allowed-value set
                                      |
                                      v
                                value membership
```

`asn1_object::publish(stream_t*)` routes to notation representation, while `publish(binary_t*)` routes to DER representation. Constraint evaluation traverses constraint nodes and constructs a runtime allowed-value set; it is neither notation rendering nor byte encoding.

The AST visitor provides traversal-oriented access. The constraint notation visitor renders constraint expressions, while the evaluator executes their meaning against the value-domain abstraction. Keeping these paths separate lets the same model support inspection, serialization, and validation without combining those responsibilities into each semantic class.

### Related tests

- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/asn.1/testvector_der.cpp`

These are source-level verification paths; this documentation update did not execute them.

## 5. Relationships
### Related areas

- `../semantic/` — semantic object hierarchy
- `../structural/` — structural node hierarchy
- `../../runtime/` — runtime schema/value handling
- `../../parser/` — parsed ASN.1 representation

### Implementation source navigation
- `sdk/io/asn.1/basic/visitor/asn1_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_ast_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_visitor.hpp`
- `sdk/io/asn.1/basic/visitor/asn1_constraint_evaluator.hpp`
