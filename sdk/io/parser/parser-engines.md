# LALR and GLR Parser Engines

## Role

The parser engines consume grammar tables and a token sequence and execute SHIFT/REDUCE style parsing.

```text
parser tokens
     │
     ▼
parser engine
 ┌───┴────────┐
 ▼            ▼
LALR(1)       GLR
 │            │
 ▼            ▼
deterministic graph-structured stack
 ACTION/GOTO  multiple paths
 └─────┬────────┘
       ▼
   parse_tree
```

Both engines implement the common `parser_t` interface.

## Common parser interface

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

## lalr1_parser

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

## glr_parser

`glr_parser` provides a generalized LR execution path.

Instead of requiring one unique action path at every point, it can preserve multiple parsing paths using a graph-structured stack.

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
                     ▼
                 parse tree
```

This makes GLR useful for grammar situations where deterministic LALR parsing cannot directly represent all alternatives.

## Why both engines exist

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

## Parse-tree integration

Both engines accept an optional `parse_tree` destination.

Parser actions therefore have two effects:

1. update parser state/stack
2. report SHIFT/REDUCE events to the parse-tree builder

See [Parse tree](parser-tree.md).

## Related source

- `lalr1_parser.*`
- `glr_parser.*`
- `types.hpp`
- `parser_sdk.*`

## Related tests

- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/testvector_parser.cpp`
- ASN.1 parser tests under `test/testcase/asn.1/`

## Related documents

- `parser-generation.md`
- `parser-tree.md`
- `lalr-vs-glr.md`
