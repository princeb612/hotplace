## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 3 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Graph and graph-structured stack testcases

## 1. Role

These tests cover two distinct structures in `sdk/base/graph`: the general weighted graph (`t_graph<T>`) and the graph-structured stack (`t_gss<STATE, VALUE>`). The GSS preserves shared parent paths and is used by GLR parsing; it is not the general graph search implementation.

## 2. Test model

```text
testcase_graph.cpp                 testcase_gss.cpp
        │                                  │
        ▼                                  ▼
t_graph<T>                           t_gss<STATE, VALUE>
        │                                  │
  ┌─────┼─────┐                     ┌──────┴──────┐
 adjacency / DFS / BFS             traverse    retrace paths
 Dijkstra / topological sort       shared parents / forks
```

The general-graph tests build search objects for specific algorithms. The GSS tests construct parent-linked nodes and exercise traversal or path retracing through shared ancestry.

| Source | Main behavior |
|---|---|
| [`testcase_graph.cpp`](testcase_graph.cpp) | Adjacency traversal, DFS, BFS, Dijkstra, source-to-destination traversal, and topological sort |
| [`testcase_gss.cpp`](testcase_gss.cpp) | Traversal across parent links, forks and merges, and path retracing |

## 3. Example: traversal versus an asserted result

In `testcase_graph.cpp`, `do_test_graph()` creates a graph search object and follows the `learn() → infer() → traverse()` sequence. The tests cover adjacency traversal, DFS, BFS, Dijkstra, and topological sorting; a string-valued graph shows that vertex payloads need not be integers.

The assertion strength differs by algorithm. Several helpers print traversal or shortest-path output and then call `_test_case.assert(true, ...)`, which records success without checking the actual sequence or distance. Topological sorting does compare the computed order against an expected list, so that case has a stronger correctness assertion.

In `testcase_gss.cpp`, a root and alternative branches are joined by a merge node. The merge's traversal can reach both parent paths. Some GSS checks compare visit counts, unique values, path lengths, or retraced paths; other output-oriented calls end with constant-true assertions.

## 4. Test and verification status

### 4.1 Source-level coverage

- **General graph:** adjacency traversal, DFS, BFS, Dijkstra, source-to-destination traversal, and topological sort.
- **GSS:** traversal across parent links, forks and merges, and path retracing.
- **Stronger checks:** topological order comparison and selected GSS count/path/value comparisons.
- **Important limitation:** a logged traversal or distance followed by a constant-true assertion is not a correctness assertion for the printed value.

### 4.2 Report evidence

The supplied `test/testcase/base/report` records these report groups:

| Report case | Result summary |
|---|---:|
| `graph<int>` | `success 50` |
| `graph<std::string>` | `success 9` |
| `GSS traverse` | `success 8` |
| `GSS retrace` | `success 5` |
| `GSS retrace - fork and merge - Ambiguity simulation` | `success 7` |

These are report-defined counts, not proof that every algorithm's output was compared with an expected value. The report does not independently identify the OS/compiler/build configuration or tested source revision.

## 5. Relationships

- [`sdk/base/graph/README.md`](../../../../sdk/base/graph/README.md) — graph and GSS implementation models.
- [`sdk/io/parser/glr_parser.cpp`](../../../../sdk/io/parser/glr_parser.cpp) — consumer of GSS ancestry/path operations.
- [`../CMakeLists.txt`](../CMakeLists.txt) — collects the testcase sources into the base test target.
- [`testcase_graph.cpp`](testcase_graph.cpp) and [`testcase_gss.cpp`](testcase_gss.cpp) — source tests described above.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation limits.

## 6. References

No external book, RFC, article, or online reference is required to explain these test flows.
