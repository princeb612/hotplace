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

## 2. Data Model

### Shared parser state and table contract

Both engines use the grammar's ACTION/GOTO table and the same parser interface. Preparation (grammar/table build or import) is separate from execution (consuming tokens). ready() indicates that the engine has a usable table; imported() identifies the imported-table path.

### GLR: graph-structured stack

The GLR engine uses gss<uint32, parse_treenode*>. A GSS node stores a parser state and an optional syntax-node value; parent links preserve alternative stack histories, and multiple active heads represent concurrent parse paths. Shared ancestors allow paths to merge instead of duplicating every complete stack.

| Intermediate data | Purpose |
|---|---|
| Active GSS head | Current end of one viable parse path |
| REDUCE production | LHS symbol and RHS length |
| gss::pop(head, rhs_len, ...) result | Ancestors reached by traversing RHS-length paths |
| GOTO state | Next state for the ancestor and reduced LHS |
| (goto_state, ancestor) key | Suppresses duplicate reduction work |
| New GSS head | Reduced path for subsequent actions |

### Parse-tree event interface

Both engines can report SHIFT and REDUCE events to an optional parse_tree. The parser state and syntax output are distinct: the stack determines which action is legal, while the tree records recognized grammar structure. The tree does not supply ASN.1 semantic validation.

## 3. Behavior Model

### LALR action sequence

The LALR engine maintains a single parser-state stack and follows one action path for each lookahead. SHIFT pushes a transition state, REDUCE pops the production's RHS length and uses GOTO for the LHS, and ACCEPT completes the parse.


### Shared preparation path

```text
set_grammar(grammar)
       │
       ├─ learn() ─► generate engine table
       │
       └─ import table ─► validate/reconstruct table
                              │
                              ▼
                         ready() == true
                              │
                              ▼
                     parse(tokens, optional tree)
```

### LALR token execution

```text
top state + lookahead terminal
             │
             ▼
           ACTION
      ┌──────┼──────────┐
      ▼      ▼          ▼
    SHIFT  REDUCE     ACCEPT
      │      │          │
 consume   pop RHS      finish
 token     states
      │      │
 push next  GOTO(state after pop, LHS)
 state       │
      └──────┴──────► continue
```

LALR keeps one stack. It does not branch into multiple parse histories when a grammar has competing actions.

### GLR reduction before shift

```text
current token + active GSS heads
                │
                ▼
       inspect REDUCE actions
                │
                ▼
      pop RHS-length paths from GSS
                │
                ▼
      each reachable ancestor + LHS
                │
                ▼
          lookup GOTO state
                │
                ▼
  deduplicate (goto_state, ancestor)
                │
                ▼
        add reduced GSS head
                │
                ▼
       process further reductions
                │
                ▼
         shift current token
```

Reduction work is performed over reachable ancestors, and equivalent resulting state/ancestor pairs are not needlessly repeated. After reductions for the current lookahead are handled, the token can be shifted along viable paths.

### Parse-tree side effects

When a tree is supplied, SHIFT records terminal symbol/value and REDUCE records production shape. These events do not change the consumer's semantic responsibility: a successful syntax tree still requires a higher-level builder to interpret its nodes.

### Source-level evidence

test_asn1_notation() in test/testcase/io/parser/testcase_parser.cpp feeds the same notation vectors to four paths: LALR build, LALR import, GLR build and GLR import. test_load_parsingtable() provides a focused imported-table example. For tree construction, follow test_asn1parser() in test/testcase/io/parser/asn1module.hpp and parse_tree.cpp.

## 4. Relationships
- `parser-generation.md` — constructs the grammar tables consumed by these engines.
- `parser-tree.md` — receives parser SHIFT/REDUCE events.
- `parsing-table-binary-format.md` — defines the imported/exported table artifact.
- `lalr-vs-glr.md` — compares the execution trade-off.
- `../../base/graph/gss.md` — GSS data structure used by GLR.

### Implementation source navigation
- `lalr1_parser.hpp`, `lalr1_parser_parse.cpp`
- `glr_parser.hpp`, `glr_parser_parse.cpp`
- `types.hpp` (`parser_t`, parser action and token types)
- `test/testcase/io/parser/testcase_parser.cpp`
