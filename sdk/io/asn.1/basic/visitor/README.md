## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — visitor responsibilities and selection     │
└──────────────────────────────────────────────┘
```

# ASN.1 Visitors

## 1. Role

The visitors separate operations on ASN.1 objects from the semantic classes themselves. They are not interchangeable traversal strategies: each has a different output or purpose. Choose one based on whether you need to walk objects, inspect their structure, render notation, encode DER, or evaluate constraints.

## 2. Data Model

| Visitor | Input / context | Result or purpose | Use it when |
|---|---|---|---|
| `asn1_visitor` | An `asn1_object*` and optional `asn1_module` | Calls a supplied callback while recursively visiting tagged types, referenced definitions, constructed components, and `SEQUENCE OF` / `SET OF` element types | You need a callback-driven walk over a schema, including resolving references through a module |
| `asn1_ast_visitor` | A `const asn1_object*` | Builds a `t_tree<asn1_ast_descriptor>` containing descriptive syntax/detail/constraint fields | You need a separate inspectable tree for debugging or AST-style display |
| `asn1_notation_visitor` | An output `stream_t*`, optionally with a value | Emits ASN.1 notation-style text from semantic objects | You need to represent or inspect the schema as notation |
| `asn1_der_visitor` | Output `binary_t*`, module context, optionally a value | Produces DER bytes from semantic objects and their values | You need the binary encoding path; this is not a notation renderer |
| `asn1_constraint_visitor` | An `asn1_constraint_t*` | Abstract dispatch interface for constraint-specific operations | You are implementing a new operation over constraint nodes |
| `asn1_constraint_notation_visitor` | Constraint, owning ASN.1 object, output stream, optional value | Renders constraint notation | You need to print constraint expressions rather than evaluate them |
| `asn1_constraint_evaluator<T>` | Constraint nodes of type `T` | Evaluates constraints into a `t_set_runtime<T>` allowed-value set | You need a runtime set for membership/constraint validation |

The first four operate on ASN.1 semantic objects or produce representations of them. The constraint visitor family operates on constraint expressions and should not be confused with general schema traversal.

## 3. Behavior Model

The practical selection rule is:

- **Walk and run a callback:** use `asn1_visitor`. A referenced type may be resolved through the supplied `asn1_module`; without the module, that resolution step is unavailable.
- **Build a separate descriptive tree:** use `asn1_ast_visitor`. It describes the existing object graph; it is not the parser's `parse_tree`.
- **Render schema notation:** use `asn1_notation_visitor`.
- **Encode a value:** use `asn1_der_visitor`, which has binary output and module/value context.
- **Render a constraint:** use `asn1_constraint_notation_visitor`.
- **Evaluate a constraint:** use `asn1_constraint_evaluator<T>` and inspect its runtime result set.

`asn1_object::publish(stream_t*)` and `publish(binary_t*)` select the notation and DER paths respectively. The constraint evaluator is a different operation; it produces an allowed-value set rather than encoded output.

### Real-code example: traverse a schema with a callback

The public usage pattern is documented in `asn1_visitor.hpp` and implemented by the `asn1_visitor` class:

```cpp
auto callback = [](asn1_object* item) -> void {
    // Inspect or collect the current semantic object.
};
asn1_visitor visitor(&module, callback);
visitor.visit(schema);
```

The module pointer lets the visitor resolve referenced definitions while traversing the semantic object graph. Use `asn1_ast_visitor` when the required result is a separate descriptive tree instead; use `asn1_object::publish()` or `asn1_module::publish()` when the required result is DER bytes. These are different operations, not interchangeable visitor modes.

## 4. Relationships
- [ASN.1 visitor architecture](../asn1-visitor.md) — visitor family in the context of the semantic model.
- [ASN.1 object model](../asn1-object-model.md) — objects visited and published.
- [Structural node model](../asn1-node.md) — structural TLV tree, distinct from semantic-object visitors.
- `../semantic/constraints/` — constraint representation and evaluation.
- `../../runtime/` — module lookup and publisher/runtime integration.
- `test/testcase/asn.1/testcase_basic2.cpp`, `testcase_basic3.cpp`, `testcase_constraints.cpp`, and `testvector_der.cpp` — source-level examples for semantic construction, constraints, and DER paths.

### Implementation source navigation

- `asn1_visitor.hpp/.cpp`
- `asn1_ast_visitor.hpp/.cpp`
- `asn1_notation_visitor.hpp/.cpp`
- `asn1_der_visitor.hpp/.cpp`
- `asn1_constraint_visitor.hpp`
- `asn1_constraint_notation_visitor.hpp/.cpp`
- `asn1_constraint_evaluator.hpp`
