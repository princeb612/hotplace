## Publication

~~~text
hotplace source tree
Edition 1 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & behavior
~~~

# Graph-Structured Stack

## 1. Role

gss.hpp implements t_gss<STATE, VALUE>, a graph-structured stack used to preserve multiple stack histories with shared ancestry. It is a generic data structure rather than a parser-specific implementation; the GLR parser supplies the state and value types it needs.

An ordinary stack has one predecessor for each entry. A GSS node can have multiple parents, so diverging parse paths can share ancestry without copying every preceding stack entry.

## 2. Data Model

### Node and stack indexes

t_gss_node<STATE, VALUE> contains:

- state — caller-defined state label.
- value — caller-defined associated value.
- parents — zero or more shared_ptr links to predecessor nodes.

t_gss contains two indexes:

- heads — the list of currently registered head nodes.
- node_map — an unordered_multimap from state to every node created with that state.

~~~text
t_gss<STATE, VALUE>
├── heads: vector<shared_ptr<node>>
├── node_map: state → node (multiple nodes per state)
└── node
    ├── state
    ├── value
    └── parents: vector<shared_ptr<node>>
~~~

Nodes are allocated with std::make_shared. Parent links share node lifetime across paths. The GSS owns VALUE according to its normal value semantics; if VALUE is a raw pointer such as parse_treenode*, the shared pointer manages the GSS node, not the pointed-to parse-tree object.



## 3. Behavior Model

### Path enumeration and traversal

`retrace_paths(start, depth, callback)` supplies a vector ordered from the selected start node toward its ancestors. Depth is the number of parent-link steps, so a complete path at depth n contains n + 1 nodes. A shared ancestor can appear in more than one reported path when the paths differ above it.

Traversal and retracing therefore differ: traversal visits each reachable node once per visited set; retracing enumerates parent paths at the requested depth.

### Create heads and extend ancestry

~~~text
push_root(state0, value0)
          │
          ▼
        root ───────────────► heads
          │
          │ push(root, state1, value1)
          ▼
        child ──────────────► heads
          │
          └── add_parent(other_parent)
                   │
                   ▼
             shared ancestry
~~~

create_node() creates and indexes a node but does not register it as a head. push(parent, state, value) creates a node, optionally adds one parent, and appends it to heads; push_root() calls push() with a null parent. add_head() can register an existing node, while clear_heads() clears only the head list and does not clear the node index or destroy nodes still referenced elsewhere.

The GSS does not automatically deduplicate heads or parent links. The caller decides which nodes represent active parser paths and when to change the head set.

### Traverse reachable nodes

~~~text
traverse_all()
    │ for each registered head
    ▼
node.traverse(visitor, visited)
    │ visit current node once
    ▼
visit each parent recursively
~~~

traverse_all() shares a visited set across all heads, so a shared ancestor is visited once during that call. traverse_from() uses a fresh visited set for the selected node. traverse_where() searches from heads until it finds the first node satisfying the predicate, then traverses from that node. traverse_by_state() finds every indexed node with the requested state and traverses from each; each traverse_from() call has its own visited set.

### Retrace paths for a reduction

~~~text
             Merge (head)
              /        \
             ▼          ▼
          branch A   branch B
              \        /
               ▼      ▼
                 Root

retrace_paths(Merge, 2, callback)
    ├── [Merge, branch A, Root]
    └── [Merge, branch B, Root]
~~~

retrace_paths() delegates to the start node's recursive retrace(). Each step appends the current node, follows each parent, and calls the callback when the requested depth reaches zero. The resulting vector starts at the selected head and proceeds toward ancestors. pop() is a wrapper around this operation; it does not remove nodes or mutate the head list.

The implementation uses a path-local visited set to avoid cycles during deeper retracing while allowing separate branches to be enumerated. A missing parent before the requested depth yields no complete path at that depth.

### Concrete caller path from `testcase_gss.cpp`

This example includes the fork-and-merge setup and the callback passed to `retrace_paths()`. The callback receives each complete path in head-to-ancestor order:

```cpp
t_gss<int, std::string> stack;

auto root = stack.create_node(0, "Root");
auto branch_a = stack.create_node(1, "A1");
auto branch_b = stack.create_node(2, "A2");
auto merge = stack.create_node(3, "Merge");

branch_a->add_parent(root);
branch_b->add_parent(root);
merge->add_parent(branch_a);
merge->add_parent(branch_b);

size_t path_count = 0;
stack.retrace_paths(merge, 2, [&](const std::vector<t_gss_node<int, std::string>::ptr>& path) {
    ++path_count;
    _test_case.assert(path.size() == 3, __FUNCTION__, "path length");
    _test_case.assert(path[0]->value == "Merge", __FUNCTION__, "head");
    _test_case.assert(path[2]->value == "Root", __FUNCTION__, "ancestor");
});

_test_case.assert(path_count == 2, __FUNCTION__, "fork and merge retrace");
```

The assertions verify that both branches produce three-node paths beginning at `Merge` and ending at `Root`. This is a project-context example because it uses the testcase assertion helper and the GSS public types. Unlike `traverse_all()`, which visits each reachable node once through a shared visited set, `retrace_paths()` enumerates distinct ancestry paths.

### Backtrack string

backtrack_string() walks from the supplied node toward its first parent until it reaches a node without parents, then prints states in root-to-head order. When a node has multiple parents, this helper follows only parents[0]; it is a single-path diagnostic and is not a complete representation of all GSS branches.

## 4. Relationships

- `test/testcase/base/graph/testcase_gss.cpp` builds a four-node fork-and-merge graph and checks that `traverse_all()` visits all four unique nodes, a linear retrace returns `[B, A, Root]` at depth two, and a fork-and-merge retrace returns two three-node paths. It does not assert every intermediate state of every traversal helper; the testcase README records those limits.
- [Graph module overview](README.md) distinguishes the GSS from the general weighted graph t_graph<T>.
- [Graph testcase suite](../../../test/testcase/base/graph/README.md) explains the exact node/path assertions and the unconditional assertions used for some traversal calls.
- sdk/io/parser/glr_parser.cpp is the parser-side GLR implementation; the GSS remains generic and has no dependency on parse-tree semantics.
- When VALUE is parse_treenode*, GSS node lifetime and parse-tree object lifetime are separate concerns.

## 5. References

- [Graph-structured stack](https://en.wikipedia.org/wiki/Graph-structured_stack) — background on the shared-ancestry stack model.
- [Cloning a directed acyclic graph](https://www.geeksforgeeks.org/dsa/clone-directed-acyclic-graph/) — graph traversal and shared-node background referenced by the source header.
