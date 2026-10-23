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
# Parser Grammar and Table Generation

## 1. Role

The generation layer turns a context-free grammar into parser states and ACTION/GOTO tables. A grammar's declared revision is serialized into the binary parsing-table header and is checked during import; the ASN.1 LALR and GLR providers declare revision 3 in the Revision 1107 source snapshot.

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

## 2. Data Model

### cfg_grammar: symbol and production source

The grammar stores terminal symbols, non-terminal symbols and production rules independently of any source input. A production relates an LHS non-terminal to an ordered RHS symbol sequence. The consumer must use terminal names that agree with its token-mapping layer.

### Generation intermediates

The generation code in cfg_grammar.cpp, cfg_grammar_lalr1.cpp and cfg_grammar_glr.cpp constructs intermediate grammar information:

- FIRST/FOLLOW sets used by lookahead-related steps;
- LR items and closure/goto results;
- discovered parser states and transitions;
- candidate ACTION entries, including competing actions where the GLR path permits them;
- GOTO transitions from a state and non-terminal to a next state.

These are generation-time structures. They are not the runtime input token stream or the runtime parser stack.

### ACTION/GOTO table

| Entry | Key | Result |
|---|---|---|
| ACTION | Parser state + lookahead terminal | SHIFT, REDUCE, ACCEPT or error/conflict representation |
| GOTO | Parser state + non-terminal | Next parser state |
| Production | Rule ID | LHS symbol and ordered RHS symbols |
| Symbol index | Symbol spelling | Internal ID connecting terminals, rules and table entries |

The LALR engine uses deterministic action selection. GLR's table/execution path can preserve multiple actions so ambiguity is represented as runtime paths rather than forced into one stack.

### binary_parsing_table: reusable artifact

The table object bridges generated in-memory structures and the serialized .ptb representation. Its logical contents include symbol strings/IDs, terminal registrations, productions, ACTION entries and GOTO entries. The file layout and integrity fields are documented separately in parsing-table-binary-format.md.

The serialized table does not contain the source lexer's vocabulary/configuration, the consumer's token-to-terminal mapper or semantic builders. Those must be reconstructed by the application.

## 3. Behavior Model

### Grammar to parser table

```text
register terminals + productions in cfg_grammar
                    │
                    ▼
            compute grammar sets
              FIRST / FOLLOW
                    │
                    ▼
         construct LR(0) closure / goto
                    │
                    ▼
            discover parser states
                    │
           ┌────────┴─────────┐
           ▼                  ▼
  LALR lookahead/action   GLR action construction
           │                  │
           ▼                  ▼
 deterministic ACTION   competing ACTION paths
           └────────┬─────────┘
                    ▼
             ACTION / GOTO table
                    │
             ┌──────┴───────┐
             ▼              ▼
          execute          serialize
       parser engine      .ptb artifact
```

The generation path is independent of any particular input string. It transforms grammar symbol and production structure into a table reusable across inputs.

### Build once, execute later

1. The consumer configures cfg_grammar and its revision.
2. The selected generation path computes state and table entries.
3. The table can be retained in memory or written through binary_parsing_table.
4. Later, the consumer imports the artifact rather than regenerating the table.
5. Import checks artifact structure and compatibility against the receiving grammar revision. It does not restore lexer configuration or token mapping.

### Revision and maintenance boundary

The table version is compared with the receiving grammar revision as a compatibility floor. A table older than the required revision returns low_version; passing this check does not prove every semantically incompatible table is safe. A grammar change should be reviewed across token registration/mapping, productions, generated artifact, parser behavior and downstream tree/semantic handling.

### Source-level evidence

test/testcase/io/parser/testcase_parser.cpp::test_asn1_notation() compares LALR and GLR parser instances in both runtime-built and imported-table forms against shared notation vectors. test_load_parsingtable() imports asn1notation.ptb and parses Type1 ::= VisibleString. Follow binary_parsing_table_write.cpp and binary_parsing_table_read.cpp for the serialization boundary.

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

### Implementation source navigation
- `cfg_grammar.hpp`, `cfg_grammar.cpp`, `cfg_grammar_lalr1.cpp`, `cfg_grammar_glr.cpp`, `cfg_grammar_rule.cpp`, `types.hpp`
- `binary_parsing_table.hpp`, `binary_parsing_table.cpp`, `binary_parsing_table_read.cpp`, `binary_parsing_table_write.cpp`
- `types.hpp`
- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/asn1module.hpp`
