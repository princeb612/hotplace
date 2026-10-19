## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Parser

## 1. Role

`sdk/io/parser` provides reusable lexical and syntactic parsing infrastructure. It separates source-text tokenization from grammar representation, parser-table construction, parser execution, and the syntax tree produced by that execution. ASN.1 is the principal consumer in this source tree, but the lexer, grammar/table model, parser engines, and parse tree are not themselves ASN.1 semantic objects.

The directory contains two related but distinct paths:

- **Lexical path:** `lexical_analyzer` recognizes source spans and stores `lexical_token` entries in `lexical_context`.
- **Grammar path:** `cfg_grammar` describes productions; generation code creates ACTION/GOTO tables; `lalr1_parser` or `glr_parser` executes those tables and can report SHIFT/REDUCE operations to `parse_tree`.

## 2. Model

### Implementation map

```text
source buffer
    │
    ▼
lexical_analyzer ──► lexical_context / lexical_token
                              │
                    token translation by consumer
                              ▼
                         parser tokens
                              │
                         cfg_grammar
                              │
                  ┌───────────┴───────────┐
                  ▼                       ▼
             LALR table               GLR table
                  └───────────┬───────────┘
                              ▼
                    binary_parsing_table
                       build or import
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
               lalr1_parser         glr_parser
                    │                   │
                    │              graph-structured
                    │                stack (GSS)
                    └─────────┬─────────┘
                              ▼
                          parse_tree
                              │
                              ▼
                   consumer-specific semantics
```

The diagram represents cooperating components, not one mandatory call chain. A consumer may supply tokens directly, build tables at runtime, or import a serialized table. The lexer does not automatically turn every lexical token into a grammar terminal: a consumer such as the ASN.1 integration must maintain the token-to-grammar mapping.

### Document map

- [Parser design and implementation notes](parser.md) — retained long-form study record, experiments, traces, and implementation history.
- [Parser lexer](parser-lexer.md) — source spans, token vocabulary, and lexical context.
- [Grammar and parsing-table generation](parser-generation.md) — grammar representation and table construction.
- [LALR/GLR parser engines](parser-engines.md) — deterministic and generalized execution paths.
- [Parse tree](parser-tree.md) — syntax structure created from parser actions.
- [LALR vs GLR](lalr-vs-glr.md) — the practical trade-off between the two engines in hotplace.
- [Parsing-table binary format](parsing-table-binary-format.md) — serialized table structure and import checks.

## 3. Important behavior and lifetime

- **Lexical tokens refer to source text.** `lexical_token` stores positions and lengths; `lexical_context` retains the source pointer and token objects. Keep the source buffer valid while code may materialize token text from those positions.
- **Lexical token IDs and grammar terminals are separate namespaces.** A consumer must map tokenization results to the terminal names expected by the grammar.
- **Table construction and table execution are separate phases.** A parser can build from a grammar or import a previously generated `binary_parsing_table`. Imported tables are checked for format, integrity, and grammar/table revision compatibility.
- **LALR and GLR have different execution behavior.** LALR follows one deterministic action path; GLR retains competing paths through a graph-structured stack.
- **The parse tree records syntax, not domain meaning.** ASN.1 types, references, tags, and constraints are built by higher-level ASN.1 code after parsing.

## 4. Example from the source tests

### Follow the lexer

`test/testcase/io/parser/testcase_lexer.cpp::test_lexer()` tokenizes a representative `PersonnelRecord` ASN.1 fragment. It first uses the basic lexer vocabulary, then registers ASN.1 tokens and enables `handle_lvalue_usertype`. The assertions compare token counts (105 and 93 for the two configurations), while the dump callback records token type, line, index, position, length, and source slice. `test_lexer_hexstring()` separately checks the token sequence for a hex-string example such as `'404B5431'H`.

### Follow parser table build and import

`test/testcase/io/parser/testcase_parser.cpp::test_asn1_notation()` obtains four parser instances from `asn1_advisor`: LALR built at runtime, LALR imported from a table, GLR built at runtime, and GLR imported from a table. It checks that each parser is ready, then runs the same notation vectors through all four paths. The vectors cover assignments, tags, constructed types, constraints, and non-assignment type notation. This is a useful way to distinguish grammar behavior from the table's origin.

`test_load_parsingtable()` directly reads `asn1notation.ptb` into a LALR parser and parses `Type1 ::= VisibleString`, making the serialized-table path explicit.

### Follow YAML-driven parser tests

`test/testcase/io/parser/testvector_parser.cpp::test_yaml_testvector_parser()` loads `testvector_parser.yml`, runs the Aho–Corasick module-boundary reducer over ASN.1 text, and compares expected ranges for module header/export/import clauses and level-/edge-trigger behavior. This exercises a context-aware pre-parser path, not the same operation as the LALR/GLR grammar parser; keep that distinction in mind when reading the results.

These descriptions identify source-level test paths and assertions; they do not claim that the tests were executed as part of this documentation update.

## 5. Relationships

- `../basic/` — payload and stream primitives used by table serialization and other I/O operations.
- `../asn.1/` — the main higher-level grammar and semantic consumer. Its lexer registration, grammar productions, table revision, and semantic builder must stay coordinated.
- `../../base/graph/gss.md` — graph-structured stack support used by GLR execution.
- `../../base/` — common containers, strings, memory, and utility infrastructure.
- `test/testcase/io/parser/` — direct lexer/parser tests, parser vectors, and the sample ASN.1 module-boundary reducer.

## 6. References

### Implementation sources

- `lexical_analyzer.hpp`, `lexical_analyzer_parse.cpp`, `lexical_token.cpp`, `lexical_context.cpp`
- `cfg_grammar.hpp`, `cfg_grammar.cpp`, `cfg_grammar_lalr1.cpp`, `cfg_grammar_glr.cpp`, `cfg_grammar_rule.cpp`
- `lalr1_parser.hpp`, `lalr1_parser_parse.cpp`, `glr_parser.hpp`, `glr_parser_parse.cpp`
- `binary_parsing_table.hpp`, `binary_parsing_table.cpp`, `binary_parsing_table_read.cpp`, `binary_parsing_table_write.cpp`
- `parse_tree.hpp`, `parse_tree.cpp`

### Test sources

- `test/testcase/io/parser/testcase_lexer.cpp`
- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/testvector_parser.cpp`
- `test/testcase/io/parser/testvector_parser.yml`
