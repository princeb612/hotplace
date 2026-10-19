## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Publisher

## 1. Role

### Role in hotplace

```text
ASN.1 notation
      |
      v
  asn1_parser
      |
      v
   parse_tree
      |
      v
 asn1_publisher
      |
      +-- grammar handlers
      |      |
      |      +-- module defaults
      |      +-- EXPORTS
      |      +-- IMPORTS
      |      +-- type assignments
      |      +-- constraints / semantic types
      |
      v
asn1_build_resultset
      |
      v
asn1_modules / asn1_module
```

The publisher does not perform lexical analysis or grammar parsing. Its input is already a parse tree, and its responsibility is to reconstruct semantic objects and module/runtime information from that tree.

## 2. Model

### Shared preparation

`asn1_publisher` has a one-time preparation phase:

```text
asn1_advisor::get_instance()->get_publisher()
          |
          v
    publisher.prepare()
          |
     +----+----+
     |         |
     v         v
prepare_    prepare_
basics()   constraints()
```

The publisher is owned by `asn1_advisor`, which returns the prepared shared publisher to parser/loader code. The advisor also owns the parser providers, making it the shared ASN.1 provider rather than a resource-only dictionary. This avoids rebuilding all grammar handlers for each parse operation.

### Build process

`build()` walks the parse tree with `parse_tree_visitor`.

For each parser action:

- `shift` creates an `asn1_semantic_node` containing the grammar symbol/value and pushes it onto the publisher context stack;
- `reduce` selects a handler for the reduced grammar symbol;
- the handler consumes semantic nodes from the context and produces the semantic result for that production;
- unregistered productions fall back to the default handler where supported.

The context contains:

```text
asn1_publisher_context
    |
    +-- semantic-node stack
    +-- temporary asn1_module
    +-- symbol list
```

`asn1_semantic_node` can carry grammar information, module defaults, an `asn1_object`, optional/default information, and constraint state while a production is being reduced.

### Module construction

The current handlers explicitly materialize ASN.1 module information, including:

- module identifier and module definition;
- `EXPLICIT TAGS`, `IMPLICIT TAGS`, and `AUTOMATIC TAGS` defaults;
- `EXTENSIBILITY IMPLIED`;
- `EXPORTS` with either an explicit symbol list or `ALL`;
- `IMPORTS` and symbol lists associated with an outer module;
- type assignments and referenced types.

This means `EXPORTS` and `IMPORTS` are not retained only as parse-tree syntax. They become runtime module information used later by `asn1_module` for representation and reference lookup.

### Parameterized assignments: current boundary

Revision 1104 adds `prepare_parameterized()` handlers for parameter/actual-parameter grammar nodes. The handlers currently reconstruct semantic stack nodes for forms such as `ParameterList`, `Parameter`, and `ActualParameterList`; this is not yet a complete template-instantiation engine. The parser → publisher probe remains disabled in the testcase entry point. Direct semantic prototypes using `asn1_parameterized_type::define()` and `specialize()` are exercised separately, but end-to-end parameter binding/substitution from ASN.1 notation remains incomplete.

### Constraint construction

Constraint productions are handled by the separately prepared constraint handlers. The publisher constructs semantic constraint objects for the ASN.1 runtime model rather than evaluating constraints itself.

```text
parse_tree
    |
    v
publisher handler
    |
    v
asn1_object / constraint object
    |
    v
runtime semantic model
```

The reusable value-domain machinery remains outside this class, under the ASN.1 constraint evaluator and `sdk/base/nostd` set-runtime components.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`

The loader testcase is also a useful concrete example: it parses ASN.1 source to a parse tree and then calls the shared publisher to construct runtime modules.

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

### Related source

- `sdk/io/asn.1/runtime/asn1_publisher.hpp`
- `sdk/io/asn.1/runtime/asn1_publisher.cpp`
- `sdk/io/asn.1/runtime/asn1_publisher_basics.cpp`
- `sdk/io/asn.1/runtime/asn1_publisher_constraints.cpp`
- `sdk/io/asn.1/asn1_advisor.hpp`
- `sdk/io/asn.1/advisor/asn1_advisor.cpp`
- `sdk/io/asn.1/runtime/asn1_module.*`
