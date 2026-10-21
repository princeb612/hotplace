## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parse Tree

## 1. Role

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

It is the bridge between parser mechanics and higher-level semantic construction. In the current GLR path, the parser reports reductions while GSS paths are being reduced, so the parse tree is the first shared representation after parser execution and before domain-specific semantic objects are built.

## 2. Data Model
### parse_treenode

Each `parse_treenode` stores:

- grammar symbol
- optional token/value text
- child nodes
- terminal/non-terminal distinction

A node can report whether it is terminal and the number of RHS children represented by the reduction.

### Building the tree

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

### Visitor

`parse_tree_visitor` provides callbacks for SHIFT and REDUCE events.

The tree can therefore be:

- printed
- traversed
- transformed
- consumed by higher-level processing

without making the parser engine itself responsible for semantic interpretation.

### Parser → semantic construction

The parse tree deliberately stops at syntax. It records grammar symbols, token values and child relationships; it does not know ASN.1-specific concepts such as `SEQUENCE`, `DEFAULT`, tags, references or constraints.

```text
generic parser
      │
      ▼
  parse_tree
      │
      ├── ASN.1 publisher/builder
      │       ▼
      │   asn1_object
      │
      └── other grammar consumers
```

This boundary is important for keeping `sdk/io/parser` reusable. ASN.1 semantic construction belongs under `sdk/io/asn.1`, while `parse_tree` remains a generic parser result.

### Parser → semantic construction

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

## 3. Behavior Model
- `on_shift()` pushes a terminal node containing the token symbol and value. `on_reduce()` creates a non-terminal node and splices the last `rhs_count` nodes from the working stack into its children in their existing order. The tree is therefore assembled from parser actions rather than by reparsing the original text.
- A completed reduction may retain a rule ID when the parser calls the overload that supplies it; the simpler overload records the LHS and RHS count without a rule ID.
- `parse_tree::clear()` deletes nodes still on its working stack and releases the parser reference registered through `set_parser()`. The root returned by `get_root()` belongs to the tree; callers should not independently delete its nodes.
- `accept(visitor)` walks children before calling the reduction visitor for a non-terminal, while terminal nodes trigger the shift callback. A visitor error stops traversal. This traversal order is post-order for reductions and can be used to inspect or transform syntax without embedding domain semantics in the parser engine.
- The tree is generic syntax. It does not resolve ASN.1 references, apply constraints, or build the ASN.1 runtime module; those responsibilities belong to the higher-level consumer.

### Source-level evidence
The parser test path begins in `test/testcase/io/parser/testcase_parser.cpp::test_asn1_notation()`, where each notation is sent through `test_asn1parser()`. To follow the tree-building mechanism itself, inspect `parse_tree.cpp`: SHIFT calls `on_shift(typestring, current_token.value)` and REDUCE calls `on_reduce(rule_id, rule.lhs, rule.rhs.size())` from the parser engines. The test's `Type1 ::= VisibleString` case is a compact input for tracing the chain from tokenization and parser actions to a `Statement → Assignment → TypeSpec`-style syntax tree.

For the consumer boundary, compare that generic tree with the ASN.1 test helpers in `test/testcase/io/parser/asn1module.hpp` and the ASN.1 semantic model under `sdk/io/asn.1/`. The tree records grammar shape; the consumer interprets that shape as ASN.1 meaning.

## 4. Relationships
### Related areas

- `../asn.1/basic/`
- `../asn.1/runtime/`

### Related document

- `parser-engines.md`

### Implementation source navigation
- `parse_tree.hpp`, `parse_tree.cpp`
- `lalr1_parser_parse.cpp`, `glr_parser_parse.cpp`
- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/asn1module.hpp`
