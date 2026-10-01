# Parse Tree

## Role

`parse_tree` records the syntactic structure produced by parser SHIFT/REDUCE actions.

```text
parser action
     │
     ├── SHIFT  → terminal node
     │
     └── REDUCE → non-terminal node
                     │
                     ▼
                 parse_tree
```

It is the bridge between parser mechanics and higher-level semantic construction.

## parse_treenode

Each `parse_treenode` stores:

- grammar symbol
- optional token/value text
- child nodes
- terminal/non-terminal distinction

A node can report whether it is terminal and the number of RHS children represented by the reduction.

## Building the tree

The parser reports two fundamental operations:

- `on_shift(token_symbol, token_value)`
- `on_reduce(lhs_symbol, rhs_count)`

The resulting tree mirrors the grammar reductions.

For example, the ASN.1 test trace for:

```text
Type1 ::= VisibleString
```

produces a structure equivalent to:

```text
Statement
  Assignment
    id
    ::=
    TypeSpec
      TypeBase
        SimpleType
          VisibleString
```

This is more than a debug display: semantic construction can use the resulting grammar structure as input to the next stage.

## Visitor

`parse_tree_visitor` provides callbacks for SHIFT and REDUCE events.

The tree can therefore be:

- printed
- traversed
- transformed
- consumed by higher-level processing

without making the parser engine itself responsible for semantic interpretation.

## Parser → semantic construction

The important architectural boundary is:

```text
source
  ↓
lexer
  ↓
parser
  ↓
parse_tree
  ↓
semantic construction
  ↓
domain object
```

For ASN.1 this is the boundary between generic parsing infrastructure and the ASN.1 semantic model described under `sdk/io/asn.1/basic/`.

## Related source

- `parse_tree.*`
- `lalr1_parser.*`
- `glr_parser.*`
- `parser_sdk.*`

## Related tests

- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/asn.1/testvector_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`

## Related areas

- `../asn.1/basic/`
- `../asn.1/runtime/`

## Related document

- `parser-engines.md`
