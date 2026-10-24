## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# ASN.1 Runtime

## 1. Role

The runtime layer represents ASN.1 modules and their types, resolves references between definitions, and provides the parser/publisher path that turns a parser-produced tree into runtime module information. It also contains weakly typed and strongly typed object representations used by later value/encoding operations.

The current module representation is `asn1_module`; `asn1_modules` is the registry for named module instances. `asn1_module_context` is historical terminology, not the current type name.

## 2. Data Model

### Main data boundaries

| Data | Meaning | Handled by |
|---|---|---|
| `parser_token` sequence | Lexical items mapped to the generic parser token model | `asn1_parser` adapter |
| `parse_tree` | Grammar-level structure and parser events | `sdk/io/parser` |
| `asn1_semantic_node` | Temporary semantic value while a production is reconstructed | Publisher context |
| `asn1_object` hierarchy | ASN.1 type/value/tag/constraint relationships | Basic semantic model and publisher handlers |
| `asn1_module` | Module identity, defaults, assignments, imports/exports, lookup context | Runtime |
| `asn1_modules` | Named module collection used for cross-module resolution | Runtime registry |

## 3. Behavior Model

### Notation-to-runtime path

```text
ASN.1 notation
    |
    v
asn1_loader (optional file/memory entry)
    |
    v
asn1_parser -- tokens --> parse_tree
                              |
                              v
                     asn1_publisher::build()
                              |
                +-------------+-------------+
                v             v             v
          module metadata  type/reference  constraints
          IMPORTS/EXPORTS  assignments    semantic nodes
                +-------------+-------------+
                              v
                         asn1_module
                              |
                              v
                        asn1_modules
                              |
                    local/imported lookup
                              |
                              v
                    runtime type/object paths
```

The generic parse tree, temporary semantic nodes, and completed runtime module/object graph are different data layers. The diagram is an architectural route, not a claim that every ASN.1 production has complete semantic handling.


### Parse-tree reconstruction

1. `asn1_parser::to_tokens()` invokes the configured lexical analyzer, skips comments, maps lexical descriptions into parser tokens, and appends the generic EOF token.
2. `to_parsetree()` selects the ASN.1 parser provider and passes tokens to the generic parser engine. The current source uses the imported GLR parser path.
3. `to_result()` obtains the shared publisher through `asn1_advisor` and calls `asn1_publisher::build()`.
4. The publisher visitor processes shift/reduce events. Shift creates temporary semantic nodes; reduce selects a production handler that consumes stack entries and constructs the semantic result.
5. The publisher populates module metadata, assignments, references, and constraint objects. Module-aware lookup then checks local definitions and imported symbol modules.

### Module and reference resolution

Declaration and resolution are separate. Creating a referenced-type node does not alone prove that its target is linked. Module-aware `search()` can consult local definitions and imported-symbol modules; `resolve()` uses those lookups to validate reference dependencies.

### Concrete use paths from the ASN.1 testcases

The publisher can be exercised directly with an already assembled generic parse tree. In `test/testcase/asn.1/runtime/testcase_publish.cpp`, the first small example records SHIFT/REDUCE events for `Type1 ::= VisibleString`, obtains the publisher from `asn1_advisor`, calls `publisher->build(&pt, result)`, and publishes `result.object`. The testcase compares the resulting notation with the expected string. This isolates semantic reconstruction from lexical analysis and parser execution.

The loader testcase follows the larger file-to-runtime path:

```text
asn1_loader::asn1file_to_tokens(parser, file, tokens)
    -> parser.to_parsetree(tokens, parse_tree)
    -> parser.to_result(parse_tree, result)
    -> asn1_modules registry
    -> module->get(name) / module->is_resolvable()
```

For each fixture, `testcase_loader.cpp` checks the status of tokenization, parsing, and result construction before continuing. It then compares the module-name list, looks up each expected module, checks its imports/exports and resolvability, and verifies selected assignment names. This is a practical example of why the stages remain separate: successful parsing is not sufficient evidence that the expected runtime module was published or that its imported references resolve.

### Completion boundaries

- The shared publisher/handler set is prepared through `asn1_advisor`; each build uses its own context and temporary module state.
- Constraint handlers construct constraint model objects; reusable range/set evaluation machinery lives separately, including under `sdk/base/nostd`.
- Parameterized notation has grammar productions and direct semantic prototypes, but the disabled end-to-end probe means parameter binding/substitution should not be represented as complete.
- Parser, publisher, imported-symbol resolution, and notation representation are exercised in distinct test stages. This documentation update did not execute those tests.

## 5. Relationships
- [ASN.1 Basic](../basic/README.md) — semantic types, structural nodes, tagging, and constraints.
- [ASN.1 parser adapter](asn1_parser.md) — tokenization and generic parse-tree construction.
- [ASN.1 publisher](asn1_publisher.md) — grammar-event handling and semantic reconstruction.
- [ASN.1 module](asn1_module.md) — module data, lookup, imports/exports, and reference resolution.
- [ASN.1 loader developer notes](../loader/asn1_loader.md) — source file to parser stages.
- [Generic parser](../../parser/README.md) — lexer, parser engines, and parse-tree infrastructure.
- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`
- `test/testcase/asn.1/loader/testcase_loader.cpp`

## 6. References

No external references are listed.

## 7. Developer Notes
The examples below preserve the earlier DER/TLV/semantic-object comparison study. They are illustrative traces for selected schemas and tag combinations, not evidence of complete ASN.1 feature coverage.

### Tagged and referenced types
#### Type1 ::= VisibleString

- DER
  - 1A 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 1A 05 V 4A 6F 6E 65 73
  - node 1 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
- weakly-typed AST
  - NODE1 VisibleString
- strongly-typed AST
  - Type1 referenced type
    - VisibleString

#### Type2 ::= [APPLICATION 3] IMPLICIT Type1

- DER
  - 43 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 43 05 V 4A 6F 6E 65 73
  - node 1 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 3]
    - ANY
- strongly-typed AST
  - Type2 referenced type
    - tagged type
      - tag type
        - [APPLICATION 3] IMPLICIT
      - Type1 referenced type
        - VisibleString

#### Type3 ::= [2] EXPLICIT Type2

- DER
  - A2 07 43 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL A2 07
  - node 1 I 0xA0 (CONTEXT+CONSTRUCTED) T 2 ([2]) L 7
    - [x] TL 43 05 V 4A 6F 6E 65 73
    - node 2 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [2] EXPLICIT
    - NODE2 tagged type
      - tag type
        - [APPLICATION 3]
      - ANY
- strongly-typed AST
  - Type3 referenced type
    - tagged type
      - tag type
        - [2] EXPLICIT
      - Type2 referenced type
        - tagged type
          - tag type
            - [APPLICATION 3] IMPLICIT
          - Type1 referenced type
            - VisibleString

#### Type4 ::= [APPLICATION 7] IMPLICIT Type3

- DER
  - 67 07 43 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 67 07
  - node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 7 ([APPLICATION 7]) L 7
    - [x] TL 43 05 V 4A 6F 6E 65 73
    - node 2 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 7] EXPLICIT
    - NODE2 tagged type
      - tag type
        - [APPLICATION 3]
      - ANY
- strongly-typed
  - Type4 referenced type
    - tagged type
      - tag type
        - [APPLICATION 7] IMPLICIT
      - Type3 referenced type
        - tagged type
          - tag type
            - [2] EXPLICIT
          - Type2 referenced type
            - tagged type
              - tag type
                - [APPLICATION 3] IMPLICIT
              - Type1 referenced type
                - VisibleString

#### Type5 ::= [2] IMPLICIT Type2

- DER
  - 82 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 82 05 V 4A 6F 6E 65 73
  - node 1 I 0x80 (CONTEXT) T 2 ([2]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [2]
    - ANY
- strongly-typed AST
  - Type5 referenced type
    - tagged type
      - tag type
        - [2] IMPLICIT
      - Type2 referenced type
        - tagged type
          - tag type
            - [APPLICATION 3] IMPLICIT
          - Type1 referenced type
            - VisibleString

#### Type6 ::= [2] EXPLICIT Type1

- DER
  - A2 07 1A 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL A2 07
  - node 1 I 0xA0 (CONTEXT+CONSTRUCTED) T 2 ([2]) L 7
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [2] EXPLICIT
    - NODE2 VisibleString
- strongly-typed AST
  - Type6 referenced type
    - tagged type
      - tag type
        - [2] EXPLICIT
      - Type1 referenced type
        - VisibleString

### Constructed SEQUENCE values

#### SEQUENCE {name VisibleString, ok BOOLEAN}

- DER
  - 30 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - [x] TL 30 0A
  - node 1 I 0x20 (UNIVERSAL+CONSTRUCTED) T 16 (SEQUENCE) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- weakly-typed AST
  - NODE1 SEQUENCE
    - NODE2 VisibleString
    - NODE3 BOOLEAN
- strongly-typed AST
  - SEQUENCE
    - name VisibleString
    - ok BOOLEAN

#### Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}

- DER
  - 30 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - Type1 referenced type
    - SEQUENCE
      - name VisibleString
      - ok BOOLEAN
- weakly-typed AST
  - [x] TL 30 0A
  - node 1 I 0x20 (UNIVERSAL+CONSTRUCTED) T 16 (SEQUENCE) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- strongly-typed AST
  - NODE1 SEQUENCE
    - NODE2 VisibleString
    - NODE3 BOOLEAN

#### Type2 ::= [APPLICATION 5] IMPLICIT Type1

- DER
  - 65 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - [x] TL 65 0A
  - node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 5 ([APPLICATION 5]) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 5] IMPLICIT
    - SEQUENCE
      - NODE2 VisibleString
      - NODE3 BOOLEAN
- strongly-typed AST
  - Type2 referenced type
    - tagged type
      - tag type
        - [APPLICATION 5] IMPLICIT
      - Type1 referenced type
        - SEQUENCE
          - name VisibleString
          - ok BOOLEAN
