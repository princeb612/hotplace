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

### parse_treenode: grammar-shaped node

A node records a grammar symbol, optional token/value text, terminal/non-terminal identity and an ordered child list. A terminal's value comes from the shifted input token. A non-terminal's children are the RHS nodes consumed by a reduction, kept in grammar order.

A completed reduction may carry the rule ID when the parser calls the overload that supplies it. Rule ID, LHS symbol and RHS child count are distinct: the rule ID identifies a production, while the child sequence represents one recognized instance.

### parse_tree: working stack and root

The tree builder maintains nodes needed to assemble reductions and exposes the completed root through get_root(). The root and descendants belong to the tree; callers should not delete them independently. clear() releases nodes still held by the working stack and the parser reference registered through set_parser().

### Visitor interface

parse_tree_visitor receives terminal SHIFT events and non-terminal REDUCE events. This permits printing, traversal or transformation without embedding grammar-specific semantic rules into the parser engine.

The tree is a syntax representation. ASN.1 types, tags, references, defaults and constraints are interpreted by the ASN.1 semantic layer, not encoded as intrinsic node types here.

## 3. Behavior Model

### Building nodes from parser events

```text
SHIFT token ──► terminal parse_treenode
                         │
REDUCE(lhs, rhs_count) ──┴──► non-terminal node
                                  ├─ child 0
                                  ├─ child 1
                                  └─ ... in RHS order
                                           │
                                           ▼
                                       parse_tree root
```


### Build nodes from parser actions

```text
parser SHIFT(symbol, token_value)
             │
             ▼
   create terminal node
             │
             ▼
      push onto work stack

parser REDUCE(rule_id, lhs, rhs_count)
             │
             ▼
   create non-terminal node
             │
             ▼
 remove last rhs_count nodes from work stack
             │
             ▼
 attach nodes as children in original order
             │
             ▼
 push reduced node back onto work stack
             │
             ▼
     completed root available
```

The tree is assembled incrementally from parser actions; it does not need to rescan the original source.

### Visitor traversal

```text
accept(visitor)
    │
    ├─ terminal node ─► shift callback
    │
    └─ non-terminal node
           │
           ▼
       visit children in order
           │
           ▼
       reduce callback after children
```

The traversal is post-order for reductions. If a visitor returns an error, traversal stops and propagates that error.

### Semantic boundary

The syntax tree is the hand-off point between generic parser execution and domain-specific construction. A consumer walks the grammar-shaped tree and builds its own semantic objects. A syntactically valid tree is not proof that input meets ASN.1 type, reference or constraint rules.

### Source-level evidence

test_asn1_notation() in test/testcase/io/parser/testcase_parser.cpp sends notation through test_asn1parser(). In parse_tree.cpp, SHIFT calls on_shift(typestring, current_token.value) and REDUCE calls on_reduce(rule_id, rule.lhs, rule.rhs.size()). The compact input Type1 ::= VisibleString is useful for tracing the Statement → Assignment → TypeSpec-style tree.

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
