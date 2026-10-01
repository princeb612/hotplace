# Graph

`graph.hpp` implements `t_graph<T>`, a generic graph whose vertices contain user-defined values and whose edges carry weight and direction.

## Model

The graph supports:

- directed and undirected edges
- integer edge weights
- vertex/edge insertion
- adjacency information
- traversal/search state kept separately from the graph representation

The implementation uses internal vertex/edge/tag structures and hash/set/list containers. Self-edges are normalized to weight zero.

## Search algorithms

`t_graph` exposes builder methods for several search views:

- `build_adjacent()` — adjacency traversal/result view
- `build_dfs()` — depth-first search
- `build_bfs()` — breadth-first search
- `build_dijkstra()` — weighted shortest-path search

The search objects use a common `graph_search` flow of `learn()`, `infer()` and `traverse()`. This keeps graph construction separate from the algorithm-specific result state.

## Topological sort

`t_graph::topological_sort()` provides ordering for directed graphs. The implementation computes in-degrees and repeatedly consumes vertices whose in-degree reaches zero. The feature was added to the graph module in the September 2026 revision history.

## Test coverage

`testcase_graph.cpp` exercises:

- integer directed/undirected graphs
- DFS/BFS/adjacency traversal
- Dijkstra shortest paths
- explicit source-to-destination traversal
- topological sorting
- string-valued graphs

## Related

- `sdk/base/stream/basic_stream.hpp` — result formatting in the testcase/examples
- `test/testcase/base/graph/testcase_graph.cpp`
- graph visualization reference noted in the source: Graph Online

## Source

- `sdk/base/graph/graph.hpp`
