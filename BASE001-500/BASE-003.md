# BASE-003 — graph visitor contracts and lifetime

- **Status:** Open — API semantics need confirmation
- **Area:** `sdk/base/graph`
- **Basis:** Revision 1107 documentation review. This is a list of questions to verify, not a completed source audit.
- **Source entry point:** [sdk/base/graph at the reviewed snapshot](https://github.com/princeb612/hotplace/tree/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/graph)

## Background

The review separated graph data representation from traversal behavior. The remaining question is whether callback signatures, result values, and object lifetime are described precisely for adjacency, DFS, BFS, and Dijkstra traversal.

## What is known

The previous review flagged callback arguments and semantics, result representation, and the lifetime of graph objects referenced by traversal results. No specific implementation defect has been confirmed here.

## Behavior path to trace

```text
source graph
    |
    v
adjacency / DFS / BFS / Dijkstra
    |
    +--> visit node or edge
    +--> invoke callback
    +--> update traversal state
    |
    v
result / path / distance
    |
    v
caller uses result while source objects remain valid?
```

## Questions

1. What exact values and references are passed to each callback?
2. Does a callback result continue, prune, stop, or report the traversal?
3. What ordering and update rules do DFS, BFS, and Dijkstra implement?
4. Do returned results own their data or refer to nodes/edges in the source graph?
5. Must the source graph outlive results? Are mutations during traversal supported?
6. Which testcase shows the intended contract?

## Next steps

Inspect graph types, builders, visitor interfaces, and each traversal implementation in the current source. Record actual signatures and lifetime rules. If the behavior is correct but unclear, adjust documentation; only consider source/test changes if a concrete defect or useful missing contract is established.

## History

- **Revision 1107:** Callback semantics, result representation, and lifetime were marked for follow-up.
- No source change or test run recorded.
