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

## 2. Data Model

### Shared provider and prepared handlers

`asn1_publisher` is provided through `asn1_advisor`, alongside ASN.1 parser providers. Its preparation phase registers and reuses grammar handlers rather than rebuilding the handler set for every tree.

The shared prepared handler set and each build's temporary context have different lifetimes.

### Per-build context

The publisher context holds a semantic-node stack, temporary module state, and symbol-related information used while productions are reduced. During `build()`, the publisher walks the parse tree through `parse_tree_visitor`. An `asn1_semantic_node` carries grammar symbol/value data and intermediate ASN.1 state such as defaults, optionality, and constraints.

```text
asn1_publisher_context
    ├── semantic-node stack
    ├── temporary asn1_module
    └── symbol list / intermediate state
```

These nodes are reconstruction intermediates, not the completed module or semantic object graph.

### Resulting runtime information

Handlers materialize module identity and defaults, including `EXPLICIT TAGS`, `IMPLICIT TAGS`, `AUTOMATIC TAGS`, and `EXTENSIBILITY IMPLIED`; `EXPORTS` lists or `ALL`; `IMPORTS` and their outer-module association; type assignments; referenced types; and semantic constraint objects. This becomes runtime state for representation and module-aware lookup rather than remaining only as parse-tree syntax.

Constraint handlers construct constraint model objects. Reusable value-domain/set machinery and constraint evaluation are separate concerns, including the ASN.1 constraint evaluator and `sdk/base/nostd` set-runtime components.

### Parameterized notation boundary

The parameterized handlers reconstruct intermediate nodes for forms such as `ParameterList`, `Parameter`, and `ActualParameterList`. Direct semantic prototypes exercise `asn1_parameterized_type::define()` and `specialize()`, but the end-to-end parser-to-publisher parameterized-instantiation probe remains disabled in the testcase entry point. This is not evidence of complete parameter binding, substitution, and instantiated runtime types.

## 3. Behavior Model

### Prepare the shared handler set

```text
asn1_advisor
    |
    v
shared asn1_publisher
    |
    v
prepare()
  ├── prepare_basics()
  ├── prepare_constraints()
  └── prepare_parameterized()
```


### Build execution

1. Obtain the prepared shared publisher through `asn1_advisor`.
2. Start a build with a parse tree and per-build publisher context.
3. The parse-tree visitor reports parser actions. Shift actions create and push `asn1_semantic_node` intermediates.
4. Reduce actions select the registered handler for the reduced grammar symbol.
5. The handler consumes intermediate nodes, constructs the production's semantic result, and places it back into the reconstruction flow.
6. Module and assignment handlers populate module/result-set state; constraint handlers construct constraint objects; import/export handlers preserve module symbol relationships.
7. The resulting runtime information becomes available for lookup, reference resolution, and representation.

```text
parse_tree action
      |
      +-- SHIFT --> push semantic intermediate
      |
      +-- REDUCE -> select production handler
                         |
                         v
                 consume stack operands
                         |
                         v
                 construct semantic result
                         |
                         v
                module / result-set state
```

### Test paths and what they prove

- `test/testcase/asn.1/runtime/testcase_publish.cpp::test_publish_babystep()` — staged parse-tree-to-semantic construction.
- `test/testcase/asn.1/loader/testcase_loader.cpp` — file load, parse tree, publisher invocation, module representation, and imported-symbol resolvability.
- `test/testcase/asn.1/testcase_basic3.cpp` — additional ASN.1 object-model behavior.

These are source-level verification paths, not a claim that the tests were run during this documentation update. A production handler or grammar rule alone does not prove every related notation feature is complete end to end.
## 5. Relationships

- [ASN.1 parser adapter](asn1_parser.md) — provides the syntax tree.
- [ASN.1 runtime](README.md) — module registry and resulting runtime representation.
- [ASN.1 module](asn1_module.md) — local/imported lookup and reference resolution.
- [ASN.1 Basic](../basic/README.md) — semantic/structural models and constraints.
- [Generic parser](../../parser/README.md) — parse-tree events and parser engines.
- `../advisor/` — shared provider implementation.
- `test/testcase/asn.1/runtime/testcase_publish.cpp`
- `test/testcase/asn.1/loader/testcase_loader.cpp`
