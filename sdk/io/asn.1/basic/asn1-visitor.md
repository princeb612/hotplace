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
# ASN.1 Visitor

## 1. Role

The visitor layer provides operations over ASN.1 semantic objects and constraint nodes without embedding every traversal or representation operation into the semantic classes. It does not traverse the separate `asn1_node` structural TLV tree.

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

`asn1_ast_visitor` builds a `t_tree<asn1_ast_descriptor>` from semantic ASN.1 object structures. It follows tagged/constructed children and referenced-type definitions, but it does not resolve and traverse reference targets through a module.

### Notation visitor

`asn1_notation_visitor` is a thin adapter that calls the object's `represent(stream, value)` method to produce ASN.1 notation-style text. The object representation methods perform the recursive rendering; the visitor itself does not walk children.

This is useful for inspecting or publishing the schema representation.

### DER visitor

`asn1_der_visitor` first uses `asn1_visitor` to update linkage across the reachable semantic-object graph, then calls the root object's `represent(binary, value)` method. It is one of the links between the semantic model and the binary encoding implementation, and requires a non-null `asn1_module`.

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

`asn1_object::publish(stream_t*)` routes to notation representation. The direct `asn1_object::publish(binary_t*)` and `asn1_value::publish(binary_t*)` wrappers currently construct `asn1_der_visitor` with a null module, while `asn1_der_visitor::visit()` unconditionally dereferences that module in its linkage callback; these convenience wrappers are unsafe as written. `asn1_module::publish(binary_t*)` supplies the module pointer and is the module-aware path. All these publish wrappers return `void`, so they do not expose visitor/encoding status. Constraint evaluation traverses constraint nodes and constructs a runtime allowed-value set; it is neither notation rendering nor byte encoding.

The generic `asn1_visitor` calls its callback for the current object, then recursively follows tagged/constructed children and resolves reference targets through the supplied module. It has no visited-set/cycle guard, so recursive schema references can recurse indefinitely. The AST visitor instead records reference names without following reference targets. The constraint notation visitor calls each constraint's `represent()` method; the templated evaluator implements `asn1_constraint_visitor`, accumulates a `t_set_runtime<T>`, and `asn1_constraints::validate()` checks membership in that result. Keeping these paths separate lets the same model support inspection, serialization, and validation without combining those responsibilities into each semantic class.

### Related tests

- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/asn.1/testvector_der.cpp`

These tests exercise module/value publication and constraint validation indirectly; there is no dedicated direct testcase for `asn1_visitor`, `asn1_ast_visitor` or `asn1_constraint_notation_visitor`. `testcase_basic1.cpp` calls `schema->publish(binary_t*)` and `testcase_basic2.cpp` calls `value->publish(binary_t*)`; both source calls reach the null-module wrapper described above. `testvector_der.cpp` uses the module-aware `module.publish(binary_t*)` path. This source audit did not execute the tests or establish runtime behavior.

## 4. Relationships
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
