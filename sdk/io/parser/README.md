## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1105                     │
│ Source basis: Revision 1105                   │
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
- [Grammar and parsing-table generation](parser-generation.md) — converts CFG productions/rules into parser tables.
- [LALR/GLR parser engines](parser-engines.md) — reconstructs and executes parser actions from the generated or imported tables.
- [Parse tree](parser-tree.md) — syntax structure created from parser actions.
- [LALR vs GLR](lalr-vs-glr.md) — the practical trade-off between the two engines in hotplace.
- [Parsing-table binary format](parsing-table-binary-format.md) — the .ptb artifact layout and import validation.

## 3. Behavior Model

### CFG-to-parse-tree flow

The three focused documents describe one lifecycle from different boundaries, not three unrelated features:

1. **CFG and rules** — `cfg_grammar` stores terminals and production rules. Grammar-generation code computes parser states and ACTION/GOTO entries.
2. **Table artifact** — `binary_parsing_table` holds the generated tables and can serialize them to or reconstruct them from a `.ptb` file. The binary format is a persistence/compatibility contract, not another parsing algorithm.
3. **Parser execution** — `lalr1_parser` follows a deterministic action path; `glr_parser` can preserve competing paths with a graph-structured stack.
4. **Tree reconstruction** — SHIFT/REDUCE events can be sent to `parse_tree`, which records syntax structure for the consumer's semantic stage.

See [Grammar and parsing-table generation](parser-generation.md) → [Parsing-table binary format](parsing-table-binary-format.md) → [LALR/GLR parser engines](parser-engines.md) → [Parse tree](parser-tree.md). Keep the format document separate because it defines the actual on-disk structure and import checks.

- **Lexical tokens refer to source text.** `lexical_token` stores positions and lengths; `lexical_context` retains the source pointer and token objects. Keep the source buffer valid while code may materialize token text from those positions.
- **Lexical token IDs and grammar terminals are separate namespaces.** A consumer must map tokenization results to the terminal names expected by the grammar.
- **Table construction and table execution are separate phases.** A parser can build from a grammar or import a previously generated `binary_parsing_table`. Imported tables are checked for format, integrity, and grammar/table revision compatibility.
- **LALR and GLR have different execution behavior.** LALR follows one deterministic action path; GLR retains competing paths through a graph-structured stack.
- **The parse tree records syntax, not domain meaning.** ASN.1 types, references, tags, and constraints are built by higher-level ASN.1 code after parsing.

### Parser execution paths

The parser separates lexical analysis, grammar/table construction, table serialization, and execution. Tests in `test/testcase/io/parser/` exercise distinct boundaries: lexer configuration and token spans; LALR/GLR parsing with runtime-built or imported tables; and a YAML-driven Aho–Corasick module-boundary reducer. The last path is a context-aware pre-parser, not the same operation as the grammar parser.

## 4. Relationships

- `../basic/` — payload and stream primitives used by table serialization and other I/O operations.
- `../asn.1/` — the main higher-level grammar and semantic consumer. Its lexer registration, grammar productions, table revision, and semantic builder must stay coordinated.
- `../../base/graph/gss.md` — graph-structured stack support used by GLR execution.
- `../../base/` — common containers, strings, memory, and utility infrastructure.
- [Parser testcase sources and vectors](../../../test/testcase/io/parser/) — lexer tests, parser vectors, and the sample ASN.1 module-boundary reducer.
- Implementation files are grouped by responsibility: `lexical_analyzer*`, `lexical_token*`, and `lexical_context*` implement lexical analysis; `cfg_grammar*` represents and builds grammar/table structures; `lalr1_parser*` and `glr_parser*` execute the parser engines; `binary_parsing_table*` reads/writes serialized tables; and `parse_tree*` records syntax structure. These are source-navigation pointers, not separate public concepts.
