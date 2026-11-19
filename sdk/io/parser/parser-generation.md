## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parser Grammar and Table Generation

## 1. Role

The generation layer turns a context-free grammar into parser states and ACTION/GOTO tables. A grammar's declared revision is serialized into the binary parsing-table header and is used as a minimum-revision check during import when the receiving parser has configured a nonzero revision. In the current ASN.1 providers, the LALR notation grammar declares revision 3 and the GLR grammar declares revision 4.

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

- FIRST/FOLLOW maps computed in the temporary context; the current table generators consume FIRST entries, but do not use the computed FOLLOW map;
- LR items and closure/goto results;
- discovered parser states and transitions;
- candidate ACTION entries, including competing actions where the GLR path permits them;
- GOTO transitions from a state and non-terminal to a next state.

These are generation-time structures. They are not the runtime input token stream or the runtime parser stack. The current FIRST/FOLLOW implementation is simplified: FIRST copies the FIRST set of only the first RHS symbol and does not model nullable/epsilon prefixes; FOLLOW adds the FIRST set of only the immediately following symbol or the LHS FOLLOW set at the end, without nullable-suffix propagation. The LALR and GLR lookahead-closure code likewise consults only the immediate next RHS symbol. Treat this as the implementation's current algorithm, not a complete general-CFG FIRST/FOLLOW implementation.

### ACTION/GOTO table

| Entry | Key | Result |
|---|---|---|
| ACTION | Parser state + lookahead terminal | SHIFT, REDUCE or ACCEPT; LALR rejects conflicting entries during generation, while GLR stores competing entries in a multimap |
| GOTO | Parser state + non-terminal | Next parser state |
| Production | Rule ID | LHS symbol and ordered RHS symbols |
| Symbol index | Symbol spelling | Internal ID connecting terminals, rules and table entries |

The LALR engine uses deterministic action selection. GLR's table stores multiple actions for a state/lookahead and its runtime attempts multiple GSS paths; this is not a claim of complete ambiguity preservation. See the source-level shift-path and parse-tree limitations in `parser-engines.md`.

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
5. Import checks the header, endian marker, body length and CRC, then applies a minimum-revision check against the receiving grammar's configured revision. This is a floor, not a proof of semantic compatibility; the current ASN.1 import accessors leave the grammar revision at its default zero, so their imports do not enforce a meaningful revision floor. Import does not restore lexer configuration or token mapping.

### Revision and maintenance boundary

The table revision is compared with the receiving grammar revision as a minimum compatibility floor. A table older than the required revision returns `low_version`; passing this check does not prove that a newer or otherwise semantically incompatible table is safe. The current ASN.1 import accessors do not set the receiving grammar revision before `read()`, so the default zero value disables a meaningful minimum check for those paths. A grammar change should be reviewed across token registration/mapping, productions, generated artifact, parser behavior and downstream tree/semantic handling.

### Source-level evidence

test/testcase/io/parser/testcase_parser.cpp::test_asn1_notation() compares LALR and GLR parser instances in both runtime-built and imported-table forms against shared notation vectors. test_load_parsingtable() imports asn1notation.ptb and parses Type1 ::= VisibleString. Follow binary_parsing_table_write.cpp and binary_parsing_table_read.cpp for the serialization boundary. These are parser-readiness/parse-status checks; they do not assert the generated FIRST/FOLLOW sets or compare a golden ACTION/GOTO table. The table import test uses a default parser revision of zero.

## 4. Relationships
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
