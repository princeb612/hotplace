## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
└──────────────────────────────────────────────┘
```

# Graph

## 1. Role

`sdk/base/graph` contains two related but distinct abstractions: a general graph with traversal and path algorithms (`t_graph<T>`), and a graph-structured stack (`gss`) that can retain shared parent paths. The latter is used by the GLR parser, where several active parse paths may coexist.

The directory is not only a collection of graph algorithms. The GSS is a specialized graph-shaped data structure; its consumer supplies parser state and semantic values.

## 2. Model

### General graph

[`graph.md`](graph.md) describes `t_graph<T>`. Vertices carry values of type `T`; edges represent directed or undirected connections and carry integer weights. Search results are built through separate search objects rather than being conflated with the underlying graph storage.

```text
t_graph<T>
   │
   ├── adjacency view
   ├── depth-first search (DFS)
   ├── breadth-first search (BFS)
   ├── Dijkstra shortest path
   └── topological sort for directed dependencies
```

### Graph-structured stack

[`gss.md`](gss.md) documents the GSS node/parent model. Multiple active heads can point into shared ancestry, avoiding the need to duplicate every stack prefix when parse alternatives diverge.

```text
head A ──┐
         ├── shared parent path ── root
head B ──┘
```

These are separate models: `t_graph<T>` provides general graph algorithms, while `gss<STATE, VALUE>` preserves stack paths and exposes path retracing.

## 3. Important behavior and lifetime

- A graph's edge direction and weight affect which algorithms are meaningful. Dijkstra's algorithm is for weighted shortest paths; topological ordering is for directed dependency graphs.
- Search objects are created from the graph using builder methods such as `build_dfs()` and `build_dijkstra()`. The caller is responsible for managing the returned search object according to the API used in the current source.
- The GSS retains parent links and active heads. A reduction path is reconstructed by walking ancestors to the depth required by the production; it is not equivalent to popping a single linear stack.
- `gss` is generic in `STATE` and `VALUE`. It should not depend on parse-tree semantics; the parser supplies its own concrete value type.
- The module's topological-sort support was added in the revision history. For exact revision history, consult `CHANGELOG.md` rather than inferring chronology from file timestamps.

## 4. Example from the source tests

### General graph algorithms

In `test/testcase/base/graph/testcase_graph.cpp`, the helper `do_test_graph()` constructs algorithm-specific search objects from a graph. For each search it calls `learn()`, `infer()`, and `traverse()`, and it also traverses from a supplied starting vertex. The testcase covers adjacency traversal, DFS, BFS, Dijkstra, and topological sorting; the string-valued graph case demonstrates that the vertex value need not be an integer.

The useful implementation trail is:

```text
testcase_graph.cpp
   └── graph.build_*()
         └── search.learn().infer()
               └── search.traverse(handler)
```

### Shared GSS ancestry

`test/testcase/base/graph/testcase_gss.cpp` creates a root, two alternative nodes, and a merge node. Both alternative nodes point to the root, and the merge node points to both alternatives. Traversal from the merge therefore visits both ancestry branches.

This small graph is a concrete way to understand why a graph-structured stack differs from a conventional stack: the merged head has more than one parent path.

## 5. Relationships

```text
sdk/base/graph/gss.hpp
        │ generic STATE / VALUE
        ▼
sdk/io/parser/glr_parser.cpp
        │ STATE = parser state
        │ VALUE = parse_treenode*
        ▼
GLR reduction and parse-tree construction
```

The GLR parser calls GSS path operations when reducing productions. The parser determines the reduction length and GOTO transition; the GSS provides the ancestor paths and shared graph structure. This dependency points from parser to base graph facilities, not from the graph module back into parser code.

## 6. References

### Implementation

- `sdk/base/graph/graph.hpp`
- `sdk/base/graph/gss.hpp`

### Tests and consumer

- `test/testcase/base/graph/testcase_graph.cpp`
- `test/testcase/base/graph/testcase_gss.cpp`
- `sdk/io/parser/glr_parser.cpp`
- `test/testcase/io/parser/` — parser-level consumer tests
