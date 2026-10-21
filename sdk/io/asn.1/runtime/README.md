## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# ASN.1 Runtime

## 1. Role

The runtime layer represents ASN.1 modules and their types, resolves references between definitions, and provides the parser/publisher path that turns a parser-produced tree into runtime module information. It also contains weakly typed and strongly typed object representations used by later value/encoding operations.

The current module representation is `asn1_module`; `asn1_modules` is the registry for named module instances. `asn1_module_context` is historical terminology, not the current type name.

## 2. Data Model
```text
ASN.1 source
    |
    v
sdk/io/parser lexer + grammar parser
    |
    v
parse_tree
    |
    v
asn1_publisher::build()
    |
    +-- module defaults / EXPORTS / IMPORTS
    +-- type assignments and references
    +-- constraints and semantic type objects
    |
    v
asn1_module  <---- lookup / reference resolution ----> imported modules
    |
    +-- weakly typed object path
    +-- strongly typed object path
    +-- BER/DER byte-oriented operations
```

The diagram separates syntax parsing, semantic publishing, module storage, and value/byte processing. The existence of runtime types does not mean every ASN.1 notation feature or every compiler/code-generation path is complete.

### Documents

- [Module implementation record](asn1_module.md) — local/imported symbol lookup, reference resolution, and module registry
- [ASN.1 parser](asn1_parser.md) — grammar/parser entry points
- [ASN.1 publisher](asn1_publisher.md) — parse-tree visitor and semantic reconstruction

## 3. Behavior Model
- A module/schema describes type definitions and constraints; a runtime object instance carries values; encoded BER/DER bytes are a separate representation.
- Module-aware `search()` can consult local definitions and imported symbol modules. `resolve()` uses that lookup to validate referenced-type dependencies; local definitions are preferred.
- The shared publisher is provided through `asn1_advisor`. Its preparation phase registers grammar handlers; each build operation reconstructs semantic objects from a parse tree.
- Parameterized notation handlers are not equivalent to a complete template-instantiation engine. See the publisher implementation notes and current testcase dispatch before describing support as end-to-end.

### Source-level evidence
`test/testcase/asn.1/runtime/testcase_parser.cpp::test_asn1parser()` sends ASN.1 assignments and constraint notation through the parser and checks the parse result. `testcase_publish.cpp::test_publish_babystep()` follows the staged parser → parse tree → semantic publishing path; related cases split basic and constraint publishing. The loader testcase at `test/testcase/asn.1/loader/testcase_loader.cpp` provides a more integrated example: it loads a file, inspects the parse-tree stages, calls the shared publisher, and checks imported-symbol resolvability.

These are source-level paths. Their presence here does not establish that they were executed during this documentation update.

## 4. Relationships
- `../basic/` — notation, type, tag, constraint, and structural models
- `../loader/` — file-loading and parse-tree entry point
- `../compiler/` — compiler-oriented direction; do not assume complete code generation
- `../../parser/` — generic lexer, grammar, parse tree, and parser engines
- `test/testcase/asn.1/runtime/` and `test/testcase/asn.1/loader/` — runtime and integration examples

### Related implementation and verification sources
- [Module implementation record](asn1_module.md)
- [ASN.1 parser](asn1_parser.md)
- [ASN.1 publisher](asn1_publisher.md)
- [ASN.1 Basic](../basic/README.md)
- [Loader](../loader/README.md)
- `asn1_module.hpp/.cpp`, `asn1_modules.hpp/.cpp`, `asn1_publisher*.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`

## 5. Development Notes

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
