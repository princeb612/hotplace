## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Graph and graph-structured stack testcases

## 1. What

The directory exercises two related but different models from [`sdk/base/graph`](../../../../sdk/base/graph/README.md):

- `t_graph<T>` represents a graph whose vertices carry values of `T`. The tests build directed and undirected graphs, then invoke adjacency traversal, DFS, BFS, Dijkstra shortest-path traversal, and topological sorting.
- `t_gss<STATE, VALUE>` represents a graph-structured stack (GSS). It retains multiple parent links when paths fork and later merge. The tests explicitly build shared ancestry, traverse nodes, and reconstruct paths.

The GSS tests are relevant to parser ambiguity handling; they should not be read as another set of ordinary graph-search tests.

## 2. How

### 2.1 Adjacency, DFS, and BFS

1. In [`testcase_graph.cpp`](testcase_graph.cpp), `do_test_graph()` builds each search object using `build_adjacent()`, `build_dfs()`, or `build_bfs()`, then calls `learn().infer()`. For each algorithm, the helper traverses once without a specified start and once from the supplied start vertex. The callback prints the source vertex and the returned list, using comma-separated values.

2. The helper is applied to several shapes rather than one graph alone:

- The integer graph `g` is the directed/undirected edge example also used by the topological-sort case, and is traversed from vertex `1`.
- `g2` is a weighted nine-vertex graph (vertices `0` through `8`) with edges such as `0–1:4`, `0–7:8`, `7–6:1`, and `2–8:2`; its traversal starts at `1`.
- `g3` is a seven-vertex undirected cyclic graph, including the cycle `1–2–3–7–1` and the additional cycle edge `3–4–5–6–3`.
- `g4` is a larger letter-labelled graph from `A` through `P`, with shared neighbors and multiple possible routes; traversal starts at `A`.
- The string graph in `test_graph2()` represents a daily activity schedule such as `get up → eat breakfast → go to work → work → go home`, with minute/hour weights on edges.

3. The current helper ends every traversal with `assert(true, ...)`. Those calls do not compare visited vertices, ordering, or adjacency contents against expected lists. The examples therefore show that the traversal methods are invoked across several graph shapes and provide diagnostic output, but they do not independently verify DFS/BFS/adjacency correctness.

### 2.2 Dijkstra shortest paths

1. The shortest-path helper similarly builds the Dijkstra object, calls `learn().infer()`, and invokes either `traverse(start, handler)` or `traverse(start, end, handler)`. The callback prints the source, destination, path, and reported distance.

2. The test applies this helper to several graph layouts: a weighted undirected graph with vertices `0` through `8`, a cyclic undirected graph, and selected start/end traversal. However, the helper's final assertion is unconditional. The emitted path and distance are not compared with an expected path or distance, so these cases are diagnostic demonstrations rather than strong shortest-path result checks.

### 2.3 Topological sort: two explicit expected orders

1. The test file checks topological sorting for both an integer graph and the string-labelled activity graph:

- In `test_graph1()`, the expected integer order is `{1, 2, 5, 4, 3, 7, 6}`.
- In `test_graph2()`, the activity graph expects `{"get up", "eat breakfast", "brush teeth (morning)", "go to work", "work", "go home", "shower", "eat dinner", "brush teeth (evening)", "go to bed", "watch tv", "dream"}`.

2. The helper prints the generated list and asserts exact list equality with the supplied expected order. This is stronger than the traversal and Dijkstra helpers because the returned sequence is checked. These are expected orders for the two constructed graphs, not a general proof of cycle detection or all valid topological orders.

### 2.4 Graph-structured stack traversal and retracing

1. In [`testcase_gss.cpp`](testcase_gss.cpp), a small graph is constructed with `Root` as the common ancestor, two branches `A1` and `A2`, and a `Merge` node with both branch nodes as parents.

2. For `traverse_all()`, the test checks that four visits occurred and that each of `Root`, `A1`, `A2`, and `Merge` appeared in the visited-value set. This checks unique node coverage for the sample graph. By contrast, the following `traverse_from()`, `traverse_where()`, and `traverse_by_state()` calls finish with unconditional assertions; their emitted output is not checked against an expected traversal sequence.

3. The retrace tests provide stronger evidence:

- **Linear retrace:** a `Root -> A -> B` parent chain is retraced from `B`; the callback checks path length 3 and the order `B, A, Root`, then the test checks exactly one path was returned.
- **Fork-and-merge retrace:** `Merge` has parents `A1` and `A2`, both descended from `Root`. The callback checks each path starts at `Merge`, ends at `Root`, and has length 3; the test checks that two paths were found. It does not explicitly assert whether the middle element is `A1` or `A2` in each callback.

4. These cases exercise selected shared-parent structures, not every ambiguity shape or arbitrary-depth graph.

## 3. Evidence

### Source-level coverage

**1. Traversal examples**

```text
graph fixture -> learn().infer() -> DFS/BFS callback -> print visited nodes
  -> unconditional assert(true, ...) in selected helpers
  -> no expected order / visited-set comparison
```

**2. Dijkstra**

```text
graph + start/end -> shortest-path traversal -> print path and distance
  -> unless an explicit expected comparison exists in that case,
     output is diagnostic, not a correctness assertion
```

**3. Topological order and GSS**

```text
topological-sort fixture -> sort -> compare returned order == expected sequence

GSS fork/merge fixture -> traverse/retrace -> compare selected nodes/paths
  -> printed links alone are not assertions
```

Coverage is limited to the fixtures and concrete values actually compared. A group report does not upgrade unconditional assertions into path-correctness checks.



The supplied [Test Report Snapshot](../../test-report-status.md) records the `graph<int>`, `graph<std::string>`, and GSS traversal/retrace groups. The report is group-level execution evidence; it does not turn unconditional assertions into checks of the paths printed by the helpers.

The report does not independently identify the tested source revision, OS, compiler, or complete build configuration.



## 4. Relationships

- [`sdk/base/graph/README.md`](../../../../sdk/base/graph/README.md) — graph and GSS implementation models.
- [`sdk/io/parser/glr_parser.cpp`](../../../../sdk/io/parser/glr_parser.cpp) — parser-side use of graph-structured stack ancestry and paths.
- [`../CMakeLists.txt`](../CMakeLists.txt) — testcase source collection.
- [`testcase_graph.cpp`](testcase_graph.cpp) and [`testcase_gss.cpp`](testcase_gss.cpp) — the direct test flows described here.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation limits.

## 5. References

No external reference is required to explain these testcase flows.
