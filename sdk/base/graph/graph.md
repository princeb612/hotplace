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

### Introduction

`graph.hpp` implements `t_graph<T>`, a generic graph whose vertices contain user-defined values and whose edges carry weight and direction.

## 2. Data Model

The graph supports:

- directed and undirected edges
- integer edge weights
- vertex/edge insertion
- adjacency information
- traversal/search state kept separately from the graph representation

The implementation uses internal vertex/edge/tag structures and hash/set/list containers. Self-edges are normalized to weight zero.

## 3. Behavior Model

### Search algorithms

`t_graph` exposes builder methods for several search views:

- `build_adjacent()` — adjacency traversal/result view
- `build_dfs()` — depth-first search
- `build_bfs()` — breadth-first search
- `build_dijkstra()` — weighted shortest-path search

The search objects use a common `graph_search` flow of `learn()`, `infer()` and `traverse()`. This keeps graph construction separate from the algorithm-specific result state. The builder methods return raw pointers to heap-allocated search objects; callers must delete them after use, as shown in `testcase_graph.cpp`.

### Topological sort

`t_graph::topological_sort()` provides ordering for directed graphs. The implementation computes in-degrees and repeatedly consumes vertices whose in-degree reaches zero. The topological-sort feature is recorded in `CHANGELOG.md` under Revision 1083. In `testcase_graph.cpp`, `do_test_graph()` exercises the search objects through `learn().infer()` and `traverse(handler)`, then checks topological ordering and a string-valued graph; the callback makes traversal order and path information observable.

## 4. Relationships

### Relationship to the graph-structured stack

`graph.hpp` and `gss.hpp` serve different purposes. `t_graph<T>` is a general graph with graph algorithms; `gss<STATE, VALUE>` is a stack-shaped graph specifically useful for retaining shared parent paths. The GLR parser uses the latter, not the weighted graph search classes described below.

```text
t_graph<T>                    gss<STATE, VALUE>
   │                                │
   ├── BFS / DFS                    ├── heads
   ├── Dijkstra                     ├── parent paths
   └── topological sort             └── retrace for reduction
```

See [gss](gss.md).

### Related

- `basic_stream.hpp` formats graph results in examples and tests. `graph.hpp` implements the general graph algorithms; `testcase_graph.cpp` exercises those algorithms, while `testcase_gss.cpp` covers the separate graph-structured stack. Graph Online is retained as a visualization resource for inspecting graph examples.

## 5. References

- Graph visualization resource retained in the original documentation: https://graphonline.ru/en/

