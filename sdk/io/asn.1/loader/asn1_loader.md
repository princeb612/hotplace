# ASN.1 Loader

## Role

`asn1_loader` is the file/stream entry point intended to load an ASN.1 notation source into the hotplace ASN.1 processing flow.

At revision 1097, the loader has taken its first implementation step: `load_file()` maps the source and `load()` passes the in-memory notation to `asn1_parser`, producing a `parse_tree`. Publishing that tree into runtime objects remains a separate second stage.

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

- `asn1_loader::load_file()` — opens an ASN.1 source file through `file_stream`, memory-maps it, and forwards the buffer to `load()`.
- `asn1_loader::load()` — constructs an in-memory buffer and invokes `asn1_parser::parse()` to populate the supplied `parse_tree`.

The current implementation is intentionally split into loading/parsing and publishing/runtime construction:

```text
ASN.1 file / memory
        |
        v
   asn1_loader
        |
        v
   asn1_parser
        |
        v
    parse_tree
        |
        v
  asn1_publisher
        |
        v
asn1_runtime_context
        |
        v
 runtime objects
```

## Relation to the parser and runtime

The loader is the file/memory entry point into the parser pipeline. It does not publish the parse tree itself; `asn1_publisher` performs the next semantic/runtime construction step.

```text
ASN.1 source
    |
    v
asn1_loader
    |
    v
parser / semantic construction
    |
    v
asn1_runtime_context
    |
    v
ASN.1 schema / runtime objects
```

The actual parser and semantic-construction machinery currently lives under `sdk/io/asn.1/runtime` and `sdk/io/parser`; the loader does not duplicate those responsibilities.

## File-loading details

`load_file()` performs:

1. null-parameter validation
2. `file_stream::open()`
3. `file_stream::begin_mmap()`
4. forwarding the mapped buffer and size to `load()`

This keeps filesystem handling separate from the actual ASN.1 processing operation.

## Current status

Revision 1097 is a **baby step**: file loading and parsing are implemented, while publishing is exercised as a separate stage by the loader testcase. The broader `loader-flow.md` remains an earlier design/study sketch and should not be read as a statement of the current implementation status.

## Related source

- `sdk/io/asn.1/loader/asn1_loader.hpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/runtime/`
- `sdk/io/parser/`

## Related tests

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/`

The loader testcase exercises the two stages separately: `loader.load_file()` builds the parse tree, then `asn1_publisher::build()` publishes it and exposes module/runtime objects through `asn1_runtime_context`.

## Related documents

- `loader-flow.md` — earlier loader flow/design sketch
- `../runtime/` — runtime representation and semantic construction
- `../../parser/` — parser implementation
