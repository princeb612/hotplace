## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Graph

## 1. Role

### Introduction

`graph.hpp` implements `t_graph<T>`, a generic graph whose vertices contain user-defined values and whose edges carry weight and direction.

## 2. Model

The graph supports:

- directed and undirected edges
- integer edge weights
- vertex/edge insertion
- adjacency information
- traversal/search state kept separately from the graph representation

The implementation uses internal vertex/edge/tag structures and hash/set/list containers. Self-edges are normalized to weight zero.

## 3. Important behavior and lifetime

### Search algorithms

`t_graph` exposes builder methods for several search views:

- `build_adjacent()` — adjacency traversal/result view
- `build_dfs()` — depth-first search
- `build_bfs()` — breadth-first search
- `build_dijkstra()` — weighted shortest-path search

The search objects use a common `graph_search` flow of `learn()`, `infer()` and `traverse()`. This keeps graph construction separate from the algorithm-specific result state.

### Topological sort

`t_graph::topological_sort()` provides ordering for directed graphs. The implementation computes in-degrees and repeatedly consumes vertices whose in-degree reaches zero. The topological-sort feature is recorded in `CHANGELOG.md` under Revision 1083.

## 4. Example from the source tests

### Search construction and traversal

In `test/testcase/base/graph/testcase_graph.cpp`, `do_test_graph()` receives a prepared graph and a start value. It creates an adjacency search, calls `learn().infer()`, traverses the result through a callback, and repeats traversal from the selected start. It then exercises DFS and BFS through the same high-level sequence.

```text
prepared t_graph<T>
       │
       ├── build_adjacent()
       ├── build_dfs()
       ├── build_bfs()
       └── build_dijkstra()
              │
              ▼
       learn().infer()
              │
              ▼
       traverse(handler)
```

The callback prints the current vertex and the path/list passed by the search object. This makes traversal order and path information visible. The testcase also covers topological ordering and a string-valued graph, so it is useful for checking both algorithm behavior and generic vertex values.

## 5. Relationships

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

- `sdk/base/stream/basic_stream.hpp` — result formatting in the testcase/examples
- `test/testcase/base/graph/testcase_graph.cpp`
- graph visualization reference noted in the source: Graph Online

## 6. References

### Implementation

- `sdk/base/graph/graph.hpp`

### Direct test and related navigation

- `test/testcase/base/graph/testcase_graph.cpp`
- `test/testcase/base/graph/testcase_gss.cpp` — the separate graph-structured stack tests
- Graph visualization resource retained in the original documentation: https://graphonline.ru/en/

