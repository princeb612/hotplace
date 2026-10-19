## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parser Grammar and Table Generation

## 1. Role

The generation layer turns a context-free grammar into parser states and ACTION/GOTO tables. A grammar's declared revision is serialized into the binary parsing-table header and is checked during import; the ASN.1 LALR and GLR providers declare revision 3 in Revision 1105.

```text
cfg_grammar
    │
    ▼
FIRST / FOLLOW
    │
    ▼
LR(0) states
    │
    ├── LALR(1) lookahead propagation
    └── GLR action construction
    │
    ▼
binary_parsing_table
```

## 2. Model

### cfg_grammar

`cfg_grammar` is the grammar description used by the parser engines.

It stores:

- production rules
- terminal symbols
- non-terminal symbols

The main construction operations are:

- `add_production(lhs, rhs)`
- `add_terminal(term)`

The parser therefore receives grammar structure independently of the input token stream.

### Temporary generation context

`cfg_grammar.cpp`, `cfg_grammar_lalr1.cpp`, and `cfg_grammar_glr.cpp` implement the grammar helpers and LALR/GLR table-generation paths. `parser_temporary_context_t` and the table types are declared in `types.hpp`.

The implementation includes operations for:

- FIRST/FOLLOW computation
- LR(0) closure
- LR(0) state construction
- LALR(1) table generation
- GLR table generation

This keeps table-generation algorithms separate from the concrete parser engine classes.

### LALR generation

The LALR path uses LR item/state information and lookahead propagation to produce deterministic ACTION/GOTO tables.

Conceptually:

```text
CFG
 │
 ├── FIRST / FOLLOW
 │
 ├── LR(0) closure / goto
 │
 └── LR(1) lookahead information
          │
          ▼
       LALR table
```

The generated actions include:

- SHIFT
- REDUCE
- ACCEPT
- ERROR

and GOTO entries map a state plus non-terminal to the next state.

### GLR generation

GLR keeps the table representation suitable for ambiguous/conflicting grammar paths rather than requiring the deterministic LALR engine to resolve every conflict.

The execution side uses a graph-structured stack, documented with the GLR engine.

### LALR and GLR as one generation pipeline

The important source-tree distinction is that LALR and GLR share the grammar and table-generation infrastructure, but their execution semantics differ:

```text
                         cfg_grammar
                             │
                             ▼
                    table-generation code
                       │            │
                       ▼            ▼
                 LALR actions   GLR actions
                       │            │
                       └──────┬─────┘
                              ▼
                    binary_parsing_table
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                lalr1_parser        glr_parser
                                        │
                                        ▼
                                      GSS
```

The binary table is therefore a reusable execution artifact, not a separate parser algorithm.

### Binary parsing table

`binary_parsing_table` provides a reusable serialized representation of generated grammar tables.

It can:

- learn from a parser
- register productions and terminals
- build ACTION/GOTO entries
- write a table file
- read a table file into a parser

This separates expensive table construction from later parser execution.

See [Parsing table binary format](parsing-table-binary-format.md) for the file representation.

## 3. Important behavior and lifetime

- Grammar construction is independent of the source text being parsed. A production describes the relationship between a left-hand non-terminal and its RHS symbols; the lexer and parser consumer must agree on terminal names.
- Table generation is a separate phase from execution. A built table can be copied into a `binary_parsing_table` and serialized so later runs can import it instead of repeating generation.
- The grammar revision is part of the serialized-table compatibility check. `binary_parsing_table::read()` clears the destination parser/grammar before loading, checks the magic and endian marker, validates the body size and CRC, and compares the table version with the grammar revision required by the receiving parser. Treat table files as generated artifacts tied to the grammar definition, not as timeless data files.
- LALR and GLR use the same broad grammar/table infrastructure but differ in how conflicts and competing actions are handled during execution. A grammar that is accepted by one path should not be assumed to have identical behavior in the other without exercising both paths.
- ASN.1 grammar maintenance crosses lexer token registration, production rules, parser table revision, and downstream parse-tree/semantic handling. A local grammar edit can therefore require coordinated updates rather than a change to one production alone.

## 4. Example from the source tests

`test/testcase/io/parser/testcase_parser.cpp::test_asn1_notation()` is the clearest end-to-end table-generation comparison. It asks `asn1_advisor` for LALR and GLR parser instances in both build and import forms, checks `ready()`, and then feeds the same notation table to all four instances. The test vectors include type assignments, tagging, nested constructed types, constraints, and standalone type notation.

The imported-table path is made explicit by `test_load_parsingtable()`: it calls `binary_parsing_table::read("asn1notation.ptb", parser)` and then parses `Type1 ::= VisibleString`. Read this alongside `binary_parsing_table_read.cpp` and `binary_parsing_table_write.cpp` to follow the artifact lifecycle from file header and blocks to reconstructed grammar/table state.

## 5. Relationships

### ASN.1 maintenance relationship

ASN.1 grammar changes typically cross several boundaries:

```text
lexer token registration
        ↓
grammar terminal
        ↓
production
        ↓
LALR table
        ↓
token mapper
        ↓
parser execution
        ↓
parse tree
```

The parser testcase README records practical rules for avoiding shift/reduce and reduce/reduce conflicts, keeping a unified start symbol, and maintaining the lexer-to-parser token mapping.

### Related documents

- `parser-lexer.md`
- `parser-engines.md`
- `parser-tree.md`
- `lalr-vs-glr.md`
- `parsing-table-binary-format.md`

## 6. References

### Related source

- `cfg_grammar.hpp`, `cfg_grammar.cpp`, `cfg_grammar_lalr1.cpp`, `cfg_grammar_glr.cpp`, `cfg_grammar_rule.cpp`, `types.hpp`
- `binary_parsing_table.hpp`, `binary_parsing_table.cpp`, `binary_parsing_table_read.cpp`, `binary_parsing_table_write.cpp`
- `types.hpp`
- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/asn1module.hpp`
