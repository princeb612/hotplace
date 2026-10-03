# Graph

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`sdk/base/graph` provides a generic weighted graph model and graph algorithms used as a reusable base facility. It also contains the graph-structured stack (`gss`) used by the GLR parser to preserve multiple reduction paths.

## Documents
- [graph](graph.md) — graph representation, search helpers, shortest path and topological sort
- [gss](gss.md) — graph-structured stack used by GLR parsing

## Relationship to parser

```text
sdk/io/parser/glr_parser
        │
        ▼
     gss<STATE, VALUE>
        │
        ├── multiple heads
        ├── shared parent paths
        └── retrace_paths() for REDUCE
```

`gss` is intentionally kept under `base/graph`: it is a reusable graph-shaped stack primitive, while `glr_parser` supplies parser states and parse-tree values.

## Related tests
- `test/testcase/base/graph/testcase_graph.cpp`

## Source
- `sdk/base/graph/graph.hpp`
