## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1107                     │
│ Source basis: Revision 1107                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```

# Parser

## 1. Role

`sdk/io/parser` provides reusable lexical and syntactic parsing infrastructure. It separates source-text tokenization from grammar representation, parser-table construction, parser execution, and the syntax tree produced by that execution. ASN.1 is the principal consumer in this source tree, but the lexer, grammar/table model, parser engines, and parse tree are not themselves ASN.1 semantic objects.

The directory contains two related but distinct paths:

- **Lexical path:** `lexical_analyzer` recognizes source spans and stores `lexical_token` entries in `lexical_context`.
- **Grammar path:** `cfg_grammar` describes productions; generation code creates ACTION/GOTO tables; `lalr1_parser` or `glr_parser` executes those tables and can report SHIFT/REDUCE operations to `parse_tree`.

## 2. Data Model

### Main representations

| Representation | Contents and role | Important boundary |
|---|---|---|
| lexical_analyzer | Token vocabulary, lookup structures and lexical options | Defines source tokenization, not grammar productions. |
| lexical_context | Source pointer/size and ordered lexical_token objects | Tokens refer to the original source; its storage must remain valid while token text is materialized. |
| lexical_token | Token ID, source offset, length, line and token index | Lexer IDs are not automatically grammar terminal IDs. |
| cfg_grammar | Terminal/non-terminal symbols and production rules | Describes valid token sequences, not source text or semantic values. |
| ACTION/GOTO tables | Parser states, action entries, transitions and productions | Generated tables can be executed or serialized. |
| binary_parsing_table | Table representation plus serialization/import operations | File layout and grammar revision are compatibility concerns. |
| Parser execution state | One state stack for LALR; active GSS heads for GLR | Same table concepts, different stack representation and conflict behavior. |
| parse_tree / parse_treenode | Grammar symbols, terminal values and ordered children | Syntax representation, not domain semantics. |

### Supporting paths

- [Parser lexer](parser-lexer.md) — source spans, token vocabulary and lexical context, before grammar parsing.
- [LALR vs GLR](lalr-vs-glr.md) — retained Developer Notes comparison.
- [Parser design and implementation notes](parser.md) — long-form study record, experiments, traces and implementation history.

## 3. Behavior Model

### Execution path across representations

```text
lexical_context ──contains──► lexical_token ──refers to──► source buffer
       │
       └── consumer mapping ──► grammar terminal symbols

cfg_grammar ──generation──► ACTION / GOTO tables
                                   │
                      ┌────────────┴────────────┐
                      ▼                         ▼
                LALR state stack            GLR GSS heads
                      └────────────┬────────────┘
                                   ▼ SHIFT / REDUCE events
                               parse_tree
                                   │
                                   ▼
                         consumer-specific semantics
```

This is a relationship map, not a mandatory single call chain. Consumers may provide parser tokens directly, generate tables at runtime, or import a serialized table. Lexer tokens, grammar symbols and semantic objects remain separate data domains.

### Follow one implementation path

Read these linked documents in order to follow the parser from grammar definition through syntax reconstruction and into ASN.1 semantics. The table artifact is a reusable branch of the flow: it can be written after build and imported before a later parse; it is not itself the parse tree.

**Follow the links from top to bottom**

[Parser entry and execution — tokens, ACTION, SHIFT/REDUCE](parser-engines.md)

↓  

[Define `cfg_grammar` and build ACTION/GOTO tables](parser-generation.md)

↓

[Persist or import the generated table](parsing-table-binary-format.md)

↓

[Execute the table and assemble the `parse_tree`](parser-engines.md) · [tree structure](parser-tree.md)

↓

[Reconstruct ASN.1 semantics](../asn.1/runtime/asn1_parser.md) → [publish semantic objects](../asn.1/runtime/asn1_publisher.md) → [runtime modules](../asn.1/runtime/README.md)

| Stage | Read next | What to understand |
|---|---|---|
| Parser entry and execution | [LALR/GLR parser engines](parser-engines.md) | How tokens enter the parser, how ACTION selects SHIFT/REDUCE, and how the two engines maintain execution state. |
| Grammar definition | [Grammar and parsing-table generation](parser-generation.md) | How `cfg_grammar` represents terminals, non-terminals and productions. |
| Build | [Grammar and parsing-table generation](parser-generation.md) | How grammar sets and LR states become ACTION/GOTO entries. This is the in-memory build stage, before persistence. |
| Binary parsing table | [Parsing-table binary format](parsing-table-binary-format.md) | How generated tables are serialized, checked and reconstructed during import. |
| Parse tree | [Parse tree](parser-tree.md) | How SHIFT/REDUCE events assemble terminals and non-terminals into a grammar-shaped tree. |
| Semantic reconstruction | [ASN.1 parser](../asn.1/runtime/asn1_parser.md) → [ASN.1 publisher](../asn.1/runtime/asn1_publisher.md) → [ASN.1 runtime](../asn.1/runtime/README.md) | How notation becomes parser tokens, how the syntax tree is published into semantic objects, and how those objects enter module/runtime structures. |

**Keep the boundaries visible:** `cfg_grammar` builds a parser table; `binary_parsing_table` persists that table; the parser executes it to produce a `parse_tree`; ASN.1 publication then reconstructs domain-specific objects. Importing a table does not produce a tree, and building a tree does not by itself complete semantic reconstruction.


### End-to-end execution paths

```text
source bytes
    │
    ▼
lexical_analyzer::parse()
    │
    ▼
lexical_context / lexical_token[]
    │
    ▼
consumer maps lexical tokens to grammar terminals
    │
    ▼
parser::parse(tokens, optional parse_tree)
    │
    ├─ LALR: ACTION → SHIFT / REDUCE / ACCEPT
    └─ GLR: reductions over GSS paths, then SHIFT
                         │
                         ▼
                 SHIFT / REDUCE callbacks
                         │
                         ▼
                     parse_tree
                         │
                         ▼
               consumer semantic builder

cfg_grammar ─► generation ─► ACTION/GOTO table ─► build or import
                                                        │
                                                        ▼
                                                  parser ready
```

### Table build and reuse

1. The consumer registers terminals and productions in cfg_grammar.
2. Generation computes parser states and ACTION/GOTO entries for the selected engine.
3. The table can be retained in memory or serialized through binary_parsing_table.
4. A later process imports the .ptb artifact, validates its structure, integrity and revision compatibility, then reconstructs the table.
5. Import does not restore lexical configuration, token mapping or semantic builders; these remain consumer responsibilities.

### Per-input parse lifecycle

1. The consumer provides tokens in the terminal vocabulary expected by the grammar.
2. The parser examines its current state and lookahead to choose actions.
3. SHIFT consumes a token and advances parser state. REDUCE recognizes a production and uses GOTO for the reduced LHS.
4. LALR maintains one deterministic path. GLR can preserve competing paths through a graph-structured stack.
5. If a parse_tree is supplied, SHIFT/REDUCE events build a generic syntax tree. The consumer interprets that tree into domain-specific objects.

Lexical errors, table-generation conflicts, .ptb integrity errors, syntax errors and domain-semantic errors belong to different boundaries. A successful syntax parse does not prove ASN.1 type, reference, tag or constraint validity.

### Concrete caller paths from `testcase_parser.cpp`

The testcase exercises table build and table import as separate ways to obtain a ready parser, then feeds the same notation inputs through both paths:

```text
asn1_advisor
  ├─ get_notation_parser_by_build()  ──► LALR table built in memory
  ├─ get_notation_parser_by_import() ──► LALR table imported
  ├─ get_parser_by_build()           ──► GLR table built in memory
  └─ get_parser_by_import()          ──► GLR table imported
                         │
                         ▼
             test_asn1parser(parser, notation, notation)
```

`test_asn1_notation()` asserts that all four parser instances are ready and iterates concrete notation strings, including assignments, tagged types, nested `SEQUENCE`/`CHOICE` forms, and constraints. The separate `test_load_parsingtable()` path reads `asn1notation.ptb` into a `lalr1_parser`, checks the read status, and parses `Type1 ::= VisibleString`. These are useful minimal examples for consumers choosing between runtime table generation and a prebuilt artifact.

The testcase does not make those paths interchangeable: the imported table still needs the matching lexer/token-to-terminal setup, and the parser's syntax result remains distinct from ASN.1 semantic publication and constraint evaluation.

## 5. Relationships
- `../basic/` — payload and stream primitives used by table serialization and other I/O operations.
- `../asn.1/` — the main higher-level grammar and semantic consumer. Its lexer registration, grammar productions, table revision, and semantic builder must stay coordinated.
- `../../base/graph/gss.md` — graph-structured stack support used by GLR execution.
- `../../base/` — common containers, strings, memory, and utility infrastructure.
- [Parser testcase sources and vectors](../../../test/testcase/io/parser/) — lexer tests, parser vectors, and the sample ASN.1 module-boundary reducer.
- Implementation files are grouped by responsibility: `lexical_analyzer*`, `lexical_token*`, and `lexical_context*` implement lexical analysis; `cfg_grammar*` represents and builds grammar/table structures; `lalr1_parser*` and `glr_parser*` execute the parser engines; `binary_parsing_table*` reads/writes serialized tables; and `parse_tree*` records syntax structure. These are source-navigation pointers, not separate public concepts.


## 6. References

No external references are listed.
