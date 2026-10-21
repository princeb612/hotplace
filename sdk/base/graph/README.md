## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Graph

## 1. Role

`sdk/base/graph` contains two related but distinct abstractions: a general graph with traversal and path algorithms (`t_graph<T>`), and a graph-structured stack (`gss`) that can retain shared parent paths. The latter is used by the GLR parser, where several active parse paths may coexist.

The directory is not only a collection of graph algorithms. The GSS is a specialized graph-shaped data structure; its consumer supplies parser state and semantic values.

## 2. Data Model

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

## 3. Behavior Model

- A graph's edge direction and weight affect which algorithms are meaningful. Dijkstra's algorithm is for weighted shortest paths; topological ordering is for directed dependency graphs.
- Search builders such as `build_adjacent()`, `build_dfs()`, `build_bfs()`, and `build_dijkstra()` return heap-allocated search objects through raw pointers. The caller must `delete` each returned object after traversal; the testcase demonstrates this explicitly. The search object is separate from the graph and its traversal state.
- The GSS retains parent links and active heads. A reduction path is reconstructed by walking ancestors to the depth required by the production; it is not equivalent to popping a single linear stack.
- `gss` is generic in `STATE` and `VALUE`. It should not depend on parse-tree semantics; the parser supplies its own concrete value type.
- The module's topological-sort support was added in the revision history. For exact revision history, consult `CHANGELOG.md` rather than inferring chronology from file timestamps.

## 4. Relationships

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

The corresponding implementation is in `graph.hpp` and `gss.hpp`; direct graph/GSS coverage is in `testcase_graph.cpp` and `testcase_gss.cpp`. Parser-level consumer tests live under `test/testcase/io/parser/`, where the shared GSS is exercised through GLR parsing.
