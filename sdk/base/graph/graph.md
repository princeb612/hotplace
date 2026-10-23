## Publication

~~~text
hotplace source tree
Edition 1 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & behavior
~~~

# Graph

## 1. Role

graph.hpp implements t_graph<T>, a generic graph whose vertices carry values of type T and whose edges carry an integer weight and direction. The public API provides edge/vertex insertion, adjacency results, DFS, BFS, Dijkstra shortest-path routes, and topological sorting.

The graph's topology and edge attributes are stored separately from temporary search state and algorithm-specific results.

## 2. Data Model

### Vertices and edges

- A vertex wraps one T value. Vertex uniqueness/order uses T comparison; edge hashing uses std::hash<T>, so T must support the operations required by these containers.
- An edge stores from, to, weight, and graph_direction_t.
- graph_directed is the default direction; graph_undirected inserts a reverse edge into the unordered edge index.
- A self-edge is assigned weight zero by edge::adjust().
- Edge equality/hash identify the endpoint pair; weight and direction are not part of edge identity. The graph therefore does not model parallel edges with the same ordered endpoints as distinct entries.

The graph keeps both unordered indexes and ordered lists:

~~~text
t_graph<T>
├── _unordered_vertices : set<vertex>
├── _unordered_edges    : unordered_set<edge>
├── _ordered_vertices   : list<vertex>
└── _ordered_edges      : list<edge>
~~~

The unordered containers support membership checks and search setup. Ordered lists preserve insertion order for callers inspecting the graph. An undirected edge is indexed in both directions, but only the inserted orientation is appended to _ordered_edges.

### Search object and result state

Each build_* method returns a raw pointer to a separate search object. The common graph_search base stores a reference to the source graph, a neighbor map, and visited flags.

| Search implementation | Data retained |
|---|---|
| graph_adjacent_list | Vertex → neighboring vertices |
| graph_dfs | Vertex → DFS visitation list |
| graph_bfs | Vertex → BFS visitation list |
| graph_dijkstra | Start → distances; destination → predecessor alternatives; start/destination/total distance → route lists |

Dijkstra retains more than one predecessor when routes have the same calculated distance. Its final result can therefore contain multiple route lists rather than a single predecessor chain.

## 3. Behavior Model

### Build the neighbor view

~~~text
t_graph<T> topology
       │ graph_search::learn()
       ▼
do_setup()
       │ clear algorithm-specific previous results
       ▼
do_preview()
       ├── create neighbor set for each vertex
       ├── initialize visited flags
       └── add edge destinations to neighbor sets
       ▼
for each vertex as a start
       ├── reset visited flags
       └── do_learn(start)
~~~

do_preview() derives the neighbor map from the graph's edge index. Directed edges contribute the forward neighbor; undirected edges contribute the reverse neighbor as well. Algorithm-specific do_learn() then builds results for each starting vertex. The graph itself is not rewritten by search.

### Adjacency, DFS, and BFS

- **Adjacency:** records each vertex's neighbors in a list. Its traversal callback reports the vertex as both from and to, weight zero, and the adjacency list as the result.
- **DFS:** starts each result list with the start vertex, then recursively appends each newly visited neighbor.
- **BFS:** starts each result list with the start vertex and uses a queue to append neighbors in breadth-first order.

Results are built for every vertex during learn(). traverse(start, handler) exposes one start vertex's result; traverse(handler) exposes results for all starts. infer() does not add a second calculation for these three algorithms.

### Dijkstra: distances, predecessors, and route expansion

~~~text
learn(start)
   │ initialize all distances to graph_infinite; start = 0
   ▼
priority queue
   │ relax each neighbor using current edge weight
   ├── shorter distance ─► replace predecessor alternatives
   └── equal distance ───► retain another predecessor
   ▼
_path[start][destination]
   │ infer()
   ▼
_route[start] = destination + total distance + path list(s)
   │ traverse(start[, destination], handler)
   ▼
callback(from, to, total_distance, path)
~~~

For each start vertex, learning calculates distances and stores predecessor alternatives. A strictly shorter candidate replaces the current predecessor set; an equal-distance candidate is added so alternative shortest routes can be emitted. infer() walks those predecessor alternatives backward to construct forward-ordered path lists. The callback receives the total route distance, not an individual edge weight.

The implementation uses integer weights and a Dijkstra priority queue but does not reject negative edge weights. Correctness therefore depends on callers using non-negative weights.

### Topological sort

topological_sort(sorted_list) is independent of the graph_search builder flow. It clears the output, calculates in-degrees, queues vertices with zero in-degree, then repeatedly emits a vertex and decrements its neighbors' in-degrees. If fewer vertices are emitted than the graph contains, the method clears the list and returns false to signal a cycle; an empty graph returns true with an empty list.

## 4. Relationships

- `test/testcase/base/graph/testcase_graph.cpp` constructs integer, character, and string-valued graphs; its helpers call `learn().infer()`, invoke traversal callbacks, and delete each heap-allocated search object. The adjacency/DFS/BFS and Dijkstra helpers end with unconditional `assert(true, ...)`, so printed routes and traversal order are diagnostic rather than compared with expected results. The topological-sort helper does compare the complete returned list with expected orders for two fixtures.
- [Graph module overview](README.md) explains how the general graph differs from the graph-structured stack.
- [Graph testcase suite](../../../test/testcase/base/graph/README.md) documents fixtures and the strength/limits of their assertions.
- basic_stream.hpp is used by testcase callbacks to format adjacency lists, routes, and distances; it is not part of the graph's topology model.
- CHANGELOG.md records project revision history. Consult it for revision chronology rather than inferring chronology from file timestamps.

## 5. References

- [Dijkstra's algorithm](https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm) — background for weighted shortest-path search.
- [Graph Online](https://graphonline.ru/en/) — graph visualization resource referenced by the original source documentation.
