## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Graph-Structured Stack

## 1. Role

### Introduction

`gss.hpp` implements `gss<STATE, VALUE>`, a graph-structured stack used by the hotplace GLR parser. Unlike an ordinary LR stack, a GSS can retain several active heads and connect them to shared parent nodes so that alternative parser paths do not have to be copied into independent stacks.

## 2. Model

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

### Operations used by GLR

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

## 3. Important behavior and lifetime

### Shared ancestry and path depth

A GSS node can have multiple parents, and multiple active heads can share ancestors. Consequently, a reduction of depth `n` must enumerate all reachable ancestor paths of the requested depth rather than repeatedly popping one mutable linear stack.

`push()` and parent-link operations affect the graph shape; `pop()` / `retrace_paths()` observe that shape. A bug can therefore appear as a missing or duplicated reduction path even when each individual node's state/value looks valid.

### Ownership and value type

The stack is templated over `STATE` and `VALUE`. The GSS stores those values and parent relationships, but parser-specific interpretation belongs to the caller. Inspect the node ownership and cleanup policy in the active implementation before changing lifetime behavior; do not assume the generic GSS owns pointed-to `VALUE` objects merely because the value type is a pointer.

## 4. Example from the source tests

### Shared-parent traversal

`test/testcase/base/graph/testcase_gss.cpp` creates four nodes: a root, two alternatives, and a merge node. The two alternatives each link to the root; the merge links to both alternatives. The test then traverses from the merge and records visited values.

```text
          merge
          /   \
       A1       A2
          \   /
           root
```

This example isolates the defining GSS property: one current head can preserve multiple histories. For parser-level reduction behavior, follow the GSS operations from `sdk/io/parser/glr_parser.cpp`; the small base testcase demonstrates graph structure, while parser tests exercise the grammar-driven use.

## 5. Relationships

### Hotplace parser relationship

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

### Why it belongs in `base/graph`

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

## 6. References

### Implementation

- `sdk/base/graph/gss.hpp`

### Direct and consumer tests

- `test/testcase/base/graph/testcase_gss.cpp`
- `sdk/io/parser/glr_parser.cpp`
- `test/testcase/io/parser/`
- `test/testcase/asn.1/` — higher-level parser consumer coverage

