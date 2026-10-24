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

sdk/base/graph provides two related but distinct abstractions:

- **t_graph<T>** stores a general weighted graph and exposes adjacency, DFS, BFS, Dijkstra shortest-path traversal, and topological sorting.
- **t_gss<STATE, VALUE>** stores a graph-structured stack (GSS). It retains multiple parent paths and is used by the GLR parser when parse alternatives can fork and merge.

The general graph is an algorithm-facing graph model; the GSS is a stack-shaped ancestry model. They share graph terminology, but their data structures and purposes are different.

```text
t_graph<T>                    gss<STATE, VALUE>
   │                                │
   ├── BFS / DFS                    ├── heads
   ├── Dijkstra                     ├── parent paths
   └── topological sort             └── retrace for reduction
```

The left side answers graph-algorithm questions: how to visit vertices, find weighted routes, or order a directed acyclic graph. The right side preserves parser alternatives: active GSS heads can share parent ancestry, and retracing walks those paths when the parser reduces a production. In short, `t_graph<T>` computes graph results; `t_gss<STATE, VALUE>` preserves multiple stack histories for GLR parsing.

## 2. Data Model

### General graph: topology and edge attributes

A vertex carries a value of type T. An edge contains source and destination vertices, an integer weight, and a direction (graph_directed or graph_undirected).

~~~text
t_graph<T>
├── vertex values
├── edge(from, to, weight, direction)
├── unordered indexes
│   ├── vertices: set
│   └── edges: unordered_set
└── insertion-order lists
    ├── vertices
    └── edges
~~~

Unordered containers support lookup and uniqueness checks; lists preserve insertion order for inspection. For an undirected edge, the implementation stores the reverse direction in the edge index as well, while the ordered edge list records the inserted edge. Edge identity compares endpoints, not weight or direction, so another edge with the same endpoint pair does not create a parallel edge with different attributes. A self-edge is normalized to weight zero.

### Search state is separate from graph storage

Each builder returns a heap-allocated search object derived from graph_search. It refers to the source graph and prepares its own neighbor map and visited flags. Algorithm-specific derived classes retain their own result structures.

| Search view | Retained result |
|---|---|
| graph_adjacent_list | Each vertex's adjacent vertices |
| graph_dfs | DFS visitation sequence per starting vertex |
| graph_bfs | BFS visitation sequence per starting vertex |
| graph_dijkstra | Distances, predecessor alternatives, and reconstructed routes |

The visitor callback exposes a result using endpoints, a weight/distance field, and a list representing the path or adjacency result.

### Graph-structured stack: shared ancestry

t_gss_node<STATE, VALUE> stores a state, a value, and shared pointers to parent nodes. t_gss retains active heads and a state-to-node multimap.

~~~text
                  active head
                      │
                  Merge node
                   /      \
                  ▼        ▼
              branch A   branch B
                  \        /
                   ▼      ▼
                  shared root
~~~

The GSS uses std::shared_ptr for node links, so a parent can remain shared by several paths. STATE and VALUE are caller-defined; the graph layer does not interpret them as parser states or parse-tree values. The node_map indexes nodes by state but does not imply that a state uniquely identifies one node.

## 3. Behavior Model

### General graph construction and search

~~~text
add_vertex() / add_edge()
          │
          ▼
t_graph<T> topology + attributes
          │ build_adjacent / build_dfs / build_bfs / build_dijkstra
          ▼
heap-allocated graph_search object
          │
          ├── learn()
          │    ├── algorithm setup
          │    ├── build neighbor view
          │    └── calculate per-start results
          ├── infer()  (algorithm-specific post-processing)
          └── traverse(handler)
               └── expose results through callback
~~~

learn() calls setup and neighbor-view construction, then clears visited flags and computes results for each vertex. infer() is a second phase: it is a no-op for adjacency, DFS, and BFS, while Dijkstra uses it to reconstruct route lists from predecessor alternatives. Callers must keep the source graph alive while using a search object and delete the raw pointer returned by a build_* method when finished.

For adjacency, DFS, and BFS, the visitor callback uses the start vertex as both endpoints and weight zero; for Dijkstra, endpoints and total distance describe a route.

### Algorithm-specific paths

- **Adjacency:** collect neighboring vertices for each vertex.
- **DFS:** recursively visit unvisited neighbors and retain a per-start visitation sequence.
- **BFS:** use a queue to visit vertices in breadth-first order and retain a per-start sequence.
- **Dijkstra:** calculate tentative distances from each start using a priority queue. A strictly shorter route replaces predecessor alternatives; an equal-distance route is retained as another predecessor. infer() expands those alternatives into path lists. The implementation does not validate weights as non-negative, so callers should not assume negative-weight support.
- **Topological sort:** compute in-degrees, enqueue zero-in-degree vertices, and decrement neighbors as each vertex is emitted. If the emitted count differs from the vertex count, the routine clears the result and returns false for a cycle. This operation is intended for directed acyclic graphs.

### Concrete caller sequence from `testcase_graph.cpp`

The example includes the callback as well as the search-object lifecycle. The callback receives the source vertex, destination vertex, distance, and path list; for Dijkstra, it formats the route and its total distance for logging.

```cpp
template <typename T>
void do_test_graph_shortest_path(t_graph<T>& graph, const T& start) {
    auto traverse_handler = [](const T& from, const T& to, int distance, const std::list<T>& path) -> void {
        basic_stream bs;
        print_style_t style("", " -> ", "");
        print(path, bs, style);

        basic_stream out;
        out << "path[" << from << "->" << to << "] " << bs
            << " (distance : " << distance << ")";
        _logger->writeln(out);
    };

    auto shortest = graph.build_dijkstra();
    shortest->learn().infer();
    shortest->traverse(start, traverse_handler);
    delete shortest;
}
```

This is the callback shape used by the templated helper in `testcase_graph.cpp`; it assumes the surrounding testcase's project logging and printing utilities are available. For a single start vertex, `traverse(start, ...)` reports the routes retained for that start. The two-endpoint overload, `traverse(start, end, ...)`, narrows reporting to a requested destination.

For adjacency, DFS, and BFS, the testcase uses a different callback formatter that prints the vertex list, then follows the same build → `learn().infer()` → `traverse()` → `delete` lifecycle. The helper's unconditional `assert(true, ...)` calls do not validate the printed traversal order; use the dedicated topological-sort expected-order comparison or a GSS path assertion when you need a checked result. `traverse()` delivers results to the caller, but it does not itself define an expected answer.

The raw pointer returned by each `build_*()` call is explicitly deleted in the testcase. Keep the source graph alive until the search object is no longer used.

### GSS push, traversal, and retracing

~~~text
push_root(state, value)
        │
        ▼
      root node
        │ push(parent, next_state, next_value)
        ▼
     child node ──► active head
        │
        └── add_parent(other_parent)
                   │
                   ▼
             shared ancestry
~~~

push() creates a new node, optionally attaches one parent, indexes the node by state, and appends it to the active-head list. add_parent() can add further ancestry links. retrace_paths() invokes a callback for each path that reaches the requested depth; the path vector is ordered from the starting head toward its ancestors. pop() is a wrapper around this path enumeration, not a destructive pop of a conventional stack.

Traversal uses a visited set to avoid revisiting the same node while walking parent links. clear_heads() clears the active-head list but does not explicitly erase the node index. backtrack_string() follows only the first parent at each step, so it represents one path rather than all ambiguous ancestry.

## 5. Relationships

- [General graph](graph.md) documents t_graph<T>, edge attributes, search builders, and topological sort.
- [Graph-structured stack](gss.md) documents t_gss<STATE, VALUE> and path operations used by GLR.
- [Graph testcase suite](../../../test/testcase/base/graph/README.md) describes direct graph/GSS tests and distinguishes asserted results from diagnostic output.
- sdk/io/parser/glr_parser.cpp is the parser-side consumer of GLR parsing infrastructure. The dependency points from parser code to the base graph primitive, not the reverse.

## 6. References

- [Graph Online](https://graphonline.ru/en/) — graph visualization tool referenced by the original source documentation.
- [Graph-structured stack](https://en.wikipedia.org/wiki/Graph-structured_stack) — background on the GSS data structure.
- [Dijkstra's algorithm](https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm) — background for weighted shortest-path search.
