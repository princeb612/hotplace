## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# LALR and GLR Parser Engines

## 1. Role

The parser engines consume grammar tables and a token sequence and execute SHIFT/REDUCE style parsing.

```text
parser tokens
     │
     ▼
parser engine
 ┌───┴──────────────┐
 ▼                  ▼
LALR(1)             GLR
 │                  │
 │                  ▼
 │              graph-structured
 │                  stack (GSS)
 │                  │
 │          ┌───────┴────────┐
 │          ▼                ▼
 │       REDUCE           SHIFT paths
 │          │                │
 └──────────┴────────────────┘
              ▼
          parse_tree
```

Both engines implement the common `parser_t` interface.

## 2. Model

### Common parser interface

The base parser abstraction provides the common lifecycle:

```text
set grammar
   ↓
learn / build
   ↓
ready
   ↓
parse(tokens, parse_tree)
```

A parser can also import a previously built `binary_parsing_table`, avoiding regeneration.

### lalr1_parser

`lalr1_parser` is the deterministic parser engine.

Its important operations are:

- `set_grammar()`
- `learn()`
- `build(binary_parsing_table*)`
- `parse()`
- `ready()`
- `imported()`

During execution it follows one ACTION/GOTO path:

```text
state + lookahead
       │
       ▼
     ACTION
       │
 ┌─────┼─────────┐
 ▼     ▼         ▼
SHIFT REDUCE   ACCEPT
```

The ASN.1 parser currently relies on this deterministic path for its grammar.

### glr_parser

`glr_parser` provides a generalized LR execution path.

Instead of requiring one unique action path at every point, it preserves multiple active paths using `gss<uint32, parse_treenode*>`. Each GSS node carries a parser state and an optional parse-tree node, while parent links retain alternative stack histories.

Conceptually:

```text
              state + lookahead
                     │
              conflicting actions
                 /       \
                ▼         ▼
             path A     path B
                \       /
                 graph stack
                     │
             gss::pop/retrace_paths
                     │
                     ▼
                 parse tree
```

This makes GLR useful for grammar situations where deterministic LALR parsing cannot directly represent all alternatives.

### GLR reduction flow

The current implementation processes reductions before shifting the next token. For a REDUCE action, it calls `gss::pop(head, rhs_len, ...)`, computes the GOTO state from each returned ancestor, suppresses duplicate reduction work with a `(goto_state, ancestor)` key, and pushes the reduced head back into the GSS.

```text
active GSS heads
      │
      ▼
 REDUCE action
      │
      ▼
gss::pop(rhs_len)
      │
      ▼
ancestor paths
      │
      ▼
GOTO(ancestor, lhs)
      │
      ▼
new GSS head
```

This is the concrete implementation reason `sdk/base/graph/gss.hpp` is part of the parser's dependency chain.

### Why both engines exist

The two engines share the same grammar/table concepts but have different execution semantics.

```text
                cfg_grammar
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       LALR(1)               GLR
       parser                parser
          │                   │
     one action path      multiple paths
```

The existing `lalr-vs-glr.md` remains the broader comparison/study document. This module record focuses on the implementation classes actually present in hotplace.

### Parse-tree integration

Both engines accept an optional `parse_tree` destination.

Parser actions therefore have two effects:

1. update parser state/stack
2. report SHIFT/REDUCE events to the parse-tree builder

See [Parse tree](parser-tree.md).

## 3. Important behavior and lifetime

- `set_grammar()` associates a grammar with a parser; `learn()` builds the engine's table from that grammar. `build(binary_parsing_table*)` exposes the generated table, while `imported()` distinguishes the imported-table path and `ready()` indicates whether the parser can execute.
- LALR execution maintains one state stack and chooses one action for each state/lookahead pair. A grammar conflict therefore has to be resolved by the generated table or grammar design; the LALR engine does not preserve alternate parses as separate live paths.
- GLR execution can keep multiple active GSS heads. During reduction it pops the RHS-length paths, obtains each ancestor, looks up the GOTO state for the reduced LHS, avoids repeating equivalent `(goto_state, ancestor)` work, and adds the reduced head. The next token is shifted after reduction processing.
- A supplied `parse_tree` is populated from SHIFT/REDUCE callbacks. It is a syntactic output, not a semantic ASN.1 object. The caller controls whether a tree is supplied and how it is consumed.
- Imported tables are an execution artifact. Their file format, checksum, and revision checks are described in `parsing-table-binary-format.md`.

## 4. Example from the source tests

In `test/testcase/io/parser/testcase_parser.cpp`, `test_asn1_notation()` obtains four paths from `asn1_advisor`: LALR build, LALR import, GLR build, and GLR import. It first asserts that each parser is ready, then runs a shared notation vector through each parser. Because the input vectors are reused, this test compares parser/table paths against the same examples rather than testing four unrelated grammars.

For a focused serialized-table example, `test_load_parsingtable()` reads `asn1notation.ptb` with `binary_parsing_table::read()` and parses `Type1 ::= VisibleString`. To inspect how parsing results become syntax nodes, follow `test_asn1parser()` in `test/testcase/io/parser/asn1module.hpp` together with `parse_tree.cpp`.

## 5. Relationships

- `parser-generation.md` — constructs the grammar tables consumed by these engines.
- `parser-tree.md` — receives parser SHIFT/REDUCE events.
- `parsing-table-binary-format.md` — defines the imported/exported table artifact.
- `lalr-vs-glr.md` — compares the execution trade-off.
- `../../base/graph/gss.md` — GSS data structure used by GLR.

## 6. References

### Related source

- `lalr1_parser.hpp`, `lalr1_parser_parse.cpp`
- `glr_parser.hpp`, `glr_parser_parse.cpp`
- `types.hpp` (`parser_t`, parser action and token types)
- `test/testcase/io/parser/testcase_parser.cpp`
