## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Graph and graph-structured stack testcases

## 1. Role

These tests cover two distinct structures in `sdk/base/graph`: the general weighted graph (`t_graph<T>`) and the graph-structured stack (`t_gss<STATE, VALUE>`). The latter preserves shared parent paths and is used by GLR parsing; it is not the general graph search implementation.

## 2. Test model

### Model

```text
testcase_graph.cpp                 testcase_gss.cpp
        │                                  │
        ▼                                  ▼
t_graph<T>                           t_gss<STATE, VALUE>
        │                                  │
  ┌─────┼─────┐                     ┌──────┴──────┐
  adjacency DFS/BFS                traverse    retrace paths
  Dijkstra / topological sort      shared parents / forks
```

## 3. Example: representative testcase flow

This document does not duplicate a standalone program. The representative testcase functions and their assertion strength are described under Source-level coverage.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Test sources and examples

#### `testcase_graph.cpp`

The test builds integer and string-valued graphs. It invokes adjacency traversal, DFS, BFS, Dijkstra searches, source-to-destination traversal, and topological sorting. The topological-sort helper compares the resulting order against an explicit expected list.

A significant limitation is visible in helpers such as `do_test_graph()` and `do_test_graph_shortest_path()`: they log traversal results and then call `_test_case.assert(true, ...)`. Those assertions record a passing case but do not verify the actual traversal order or shortest-path distance. Topological sorting has a meaningful equality check (`expect == sorted`).

#### `testcase_gss.cpp`

The tests create parent-linked nodes, including fork-and-merge shapes. Several checks validate visit counts, unique values, path lengths, and retraced paths. Other traversal calls are followed by constant-true assertions, so their output is illustrative rather than an asserted result.

### 4.2 Documentation and verification status

#### Report-backed runtime status

The supplied `test/testcase/base/report` records:

| Report case | Result summary |
|---|---:|
| `graph<int>` | `success 50` |
| `graph<std::string>` | `success 9` |
| `GSS traverse` | `success 8` |
| `GSS retrace` | `success 5` |
| `GSS retrace - fork and merge - Ambiguity simulation` | `success 7` |

These are report-defined case counts, not a statement that every algorithmic output is asserted. The report does not establish the OS/compiler/build configuration or source revision.

#### Documentation and verification status

| Axis | Status | Basis |
|---|---|---|
| Documentation completeness | Partial | Main structures and test flows are mapped; not every graph algorithm edge case is enumerated. |
| Verification completeness | Partial | Topological sort and GSS path checks contain explicit comparisons, while several graph traversal/shortest-path helpers only log output and assert `true`. |
| Runtime execution | Report recorded | All five named graph/GSS groups above appear as successful in the supplied base report. |

#### Source basis

Source and testcase structure reviewed against hotplace revision 1104. Runtime results come from the supplied report archive; its metadata does not independently identify the tested revision.

## 5. Relationships

- [`sdk/base/graph/graph.md`](../../../../sdk/base/graph/graph.md) — general graph model and algorithms.
- [`sdk/base/graph/gss.md`](../../../../sdk/base/graph/gss.md) — graph-structured stack and shared parent paths.
- `sdk/io/parser/glr_parser` consumes GSS-like path structure for ambiguous parsing.

## 6. References

Source paths and report provenance are recorded where available.
