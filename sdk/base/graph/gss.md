# Graph-Structured Stack

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`gss.hpp` implements `gss<STATE, VALUE>`, a graph-structured stack used by the hotplace GLR parser. Unlike an ordinary LR stack, a GSS can retain several active heads and connect them to shared parent nodes so that alternative parser paths do not have to be copied into independent stacks.

## Model

```text
                 GSS
                  │
          ┌───────┴──────────┐
          ▼                  ▼
       head A            head B
          │                  │
          └── shared path ───┘
                  │
               parent
                  │
                root
```

Each `gss_node<STATE, VALUE>` stores a parser/application state, an associated value, and zero or more parent nodes. `gss` maintains active `heads` and an index of nodes by state.

## Operations used by GLR

The GLR parser currently uses the following operations:

- `push_root()` — create the initial state-0 node.
- `push()` — create a new state/value node connected to an ancestor and add it as a head.
- `get_heads()` — obtain the active parser paths.
- `pop()` — retrace parent paths for a reduction depth.
- `retrace_paths()` — enumerate paths of a requested depth without flattening the graph into separate stacks.
- `traverse_*()` — generic graph traversal helpers.

The important parser operation is `pop()`: a GLR REDUCE action needs every relevant ancestor path of the production's RHS length. The parser then looks up the GOTO state from each ancestor and pushes the reduced node back into the GSS.

```text
GLR REDUCE
    │
    ▼
gss::pop(head, rhs_len)
    │
    ▼
ancestor paths
    │
    ├── path 1 → GOTO → new head
    ├── path 2 → GOTO → new head
    └── ...
```

## Hotplace parser relationship

The concrete GLR value type is currently a `parse_treenode*`:

```cpp
using parse_gss = gss<uint32, parse_treenode*>;
```

This keeps the generic GSS independent of parsing semantics while allowing `glr_parser` to associate parser states with parse-tree nodes.

```text
sdk/base/graph/gss.hpp
        │
        │ generic STATE / VALUE
        ▼
sdk/io/parser/glr_parser.cpp
        │
        │ STATE = parser state
        │ VALUE = parse_treenode*
        ▼
parse-tree construction
```

## Why it belongs in `base/graph`

The GSS is not an ASN.1-specific structure. It is a graph-shaped stack primitive whose immediate consumer is the GLR parser. Keeping it in `base/graph` makes the dependency direction explicit:

```text
base/graph
     ▲
     │
 io/parser/glr
     ▲
     │
 io/asn.1
```

The parser therefore depends on the graph infrastructure; the graph module does not depend on the parser.

## Source and tests

- `sdk/base/graph/gss.hpp`
- `sdk/io/parser/glr_parser.cpp`
- `test/testcase/io/parser/`
- `test/testcase/asn.1/` — higher-level consumers
