# Parser Grammar and Table Generation

## Role

The generation layer turns a context-free grammar into parser states and ACTION/GOTO tables.

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

## cfg_grammar

`cfg_grammar` is the grammar description used by the parser engines.

It stores:

- production rules
- terminal symbols
- non-terminal symbols

The main construction operations are:

- `add_production(lhs, rhs)`
- `add_terminal(term)`

The parser therefore receives grammar structure independently of the input token stream.

## Temporary generation context

`parser_sdk.hpp` contains the reusable algorithms and temporary structures used during table generation.

The implementation includes operations for:

- FIRST/FOLLOW computation
- LR(0) closure
- LR(0) state construction
- LALR(1) table generation
- GLR table generation

This keeps table-generation algorithms separate from the concrete parser engine classes.

## LALR generation

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

## GLR generation

GLR keeps the table representation suitable for ambiguous/conflicting grammar paths rather than requiring the deterministic LALR engine to resolve every conflict.

The execution side uses a graph-structured stack, documented with the GLR engine.

## Binary parsing table

`binary_parsing_table` provides a reusable serialized representation of generated grammar tables.

It can:

- learn from a parser
- register productions and terminals
- build ACTION/GOTO entries
- write a table file
- read a table file into a parser

This separates expensive table construction from later parser execution.

See [Parsing table binary format](parsing-table-binary-format.md) for the file representation.

## ASN.1 maintenance relationship

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

## Related source

- `cfg_grammar.*`
- `parser_sdk.*`
- `binary_parsing_table.*`
- `types.hpp`

## Related tests

- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/asn1_cfg_parameterized.cpp`
- `test/testcase/io/parser/asn1module.cpp`
- `test/testcase/io/parser/testvector_parser.cpp`

## Related documents

- `parser-lexer.md`
- `parser-engines.md`
- `parser-tree.md`
- `lalr-vs-glr.md`
- `parsing-table-binary-format.md`
