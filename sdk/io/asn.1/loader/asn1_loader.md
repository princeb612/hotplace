# ASN.1 Loader

## Role

`asn1_loader` is the file/stream entry point intended to load an ASN.1 notation source into the hotplace ASN.1 processing flow.

At revision 1095, the loader is **not yet a completed parser-to-runtime implementation**. The public interface and file-loading path exist, while the actual `load(const char*, size_t, std::string&)` operation is still a skeleton.

## Current implementation

The module exposes two static entry points:

- `asn1_loader::load_file()` — opens an ASN.1 source file through `file_stream`, memory-maps it, and forwards the buffer to `load()`.
- `asn1_loader::load()` — intended to process an in-memory ASN.1 notation buffer; currently returns success without performing the loading operation.

The intended usage shown in the header is:

```text
ASN.1 file / memory
        |
        v
   asn1_loader
        |
        v
 ASN.1 parsing / runtime context
        |
        v
asn1_runtime_context::select(name)
```

The `name` output parameter is intended to identify the loaded module/schema for later selection through `asn1_runtime_context`.

## Relation to the parser and runtime

The loader sits between external ASN.1 notation and the parser/runtime pipeline.

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

The important point for future maintenance is that this module is a **defined integration point, not a finished loader**.

The existing `loader-flow.md` describes a broader loader flow, but the revision-1095 source should be treated as authoritative for implementation status.

## Related source

- `sdk/io/asn.1/loader/asn1_loader.hpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/runtime/`
- `sdk/io/parser/`

## Related tests

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/`

The loader testcase currently establishes the testcase entry point but does not yet exercise a completed loading pipeline.

## Related documents

- `loader-flow.md` — earlier loader flow/design sketch
- `../runtime/` — runtime representation and semantic construction
- `../../parser/` — parser implementation
