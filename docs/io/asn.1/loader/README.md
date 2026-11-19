# ASN.1 Loader

> Source base : Revision 1132

## Context

`asn1_loader` is the source-input adapter for ASN.1 notation. It accepts an in-memory notation buffer or a file and produces a generic `parse_tree`. It deliberately does not own ASN.1 grammar productions, semantic publication, or the module registry.

The current flow is split across distinct components:

```text
ASN.1 file / memory
       |
       v
  asn1_loader
       |
       v
  asn1_parser
       |
       +-- tokens
       |
       v
   parse_tree
       |
       v
 asn1_publisher::build()
       |
       v
asn1_build_resultset
       |
       v
 asn1_module / asn1_modules
       |
       v
search / resolve / is_resolvable
```

The diagram describes the cooperating implementation path. It does not mean that `asn1_loader` itself constructs or registers the runtime module.

## 1. Loader API and responsibilities

The current public entry points in `sdk/io/asn.1/loader/asn1_loader.hpp` are:

| API | Input | Output / responsibility |
|---|---|---|
| `load_file(path, parse_tree*)` | ASN.1 file path | Reads the file, tokenizes through the ASN.1 parser adapter, and creates a parse tree |
| `load(buffer, size, parse_tree*)` | In-memory ASN.1 notation | Parses the supplied notation into a parse tree |
| `asn1file_to_tokens(parser, path, tokens)` | Parser adapter and file path | Exposes the file-to-token stage separately |

The distinction is important:

- `load_file()` and `load()` produce syntax trees, not `asn1_module` objects.
- Semantic construction is performed by `asn1_publisher::build()`.
- `asn1_parser::to_result()` is a convenience bridge that obtains the shared publisher from `asn1_advisor` and calls `build()`.
- `asn1_modules` is the named-module registry; it is not owned by the loader.

For callers that want the complete notation-to-result convenience path, `asn1_parser::parse(notation, result)` combines parsing and publication. Callers that need to inspect the intermediate syntax tree can use the loader/parser tree overloads and invoke the publisher separately.

## 2. Source-level execution paths

### Ordinary module fixtures

`test/testcase/asn.1/loader/testcase_loader.cpp` registers two active procedures through `testcase_loader()`:

1. `test_asn1loader_babystep()` loads `example3.asn1` with `load_file()`, calls the publisher explicitly, checks the resulting module names, looks up the expected module, and inspects selected definitions.
2. `test_loader()` iterates `example1.asn1` through `example5.asn1`. It exposes file-to-token conversion, parse-tree construction, and publisher result construction as separate stages, then checks expected module names, selected assignments, imports/exports, and `is_resolvable()`.

These tests demonstrate the current file → tokens → parse tree → publisher → module path. They do not establish complete grammar coverage, exhaustive malformed-input recovery, or every possible import/reference dependency combination.

### Parameterized notation

The separate active `testcase_parameterized()` group also uses the loader:

- `test_parameterized2()` calls `asn1_loader::load()` for inline `FRAME` / `MyPacket` notation, then calls `asn1_publisher::build()` and compares the reconstructed module representation.
- `test_parameterized3()` calls `asn1_loader::load_file()` for `example6.asn1`, then publishes the parse tree and checks the module kind, module name, and reconstructed `Envelope {INTEGER}` representation.

These are bounded parser/loader/publisher integration cases. The broader `example7.asn1` vector remains commented out; the active tests do not prove complete support for every parameterized ASN.1 form.

## 3. Module/runtime boundary

The loader's output is a `parse_tree`. The publisher turns that tree into an `asn1_build_resultset`, whose module names and semantic objects are registered in `asn1_modules`. The resulting `asn1_module` stores module-level information such as definitions, tagging defaults, exports, imports, and references.

The module APIs then provide distinct operations:

- `get()` for local object lookup;
- `search()` for local and imported-symbol lookup;
- `resolve()` for reference dependency resolution;
- `is_resolvable()` for checking whether the selected module/object references can be resolved;
- `represent()` for regenerating module notation.

This separation keeps source acquisition, syntax parsing, semantic reconstruction, and cross-module resolution independently inspectable.

## 4. Current limitations and evidence boundaries

- A successful `load()` or `load_file()` means that the input reached a parse tree; it does not by itself prove successful semantic publication or reference resolution.
- A successful publisher result for selected fixtures does not establish complete ASN.1 grammar or semantic conformance.
- Parameterized parser/loader/publisher integration is active for the inline `FRAME` case and file-based `example6.asn1` case, but the broader `example7.asn1` vector remains in progress.
- The ASN.1 compiler directory remains a design/documentation artifact; the loader is not a source-to-C++ compiler.
- The supplied aggregate ASN.1 test report is historical runtime evidence associated with Revision 1104 context. This document's Source base is Revision 1132; no test execution is claimed by this documentation update.

## 5. Related implementation and tests

- [SDK loader implementation notes](../../../../sdk/io/asn.1/loader/asn1_loader.md)
- [ASN.1 parser adapter](../../../../sdk/io/asn.1/runtime/asn1_parser.md)
- [ASN.1 publisher](../../../../sdk/io/asn.1/runtime/asn1_publisher.md)
- [ASN.1 module runtime](../../../../sdk/io/asn.1/runtime/asn1_module.md)
- [Loader testcase](../../../../test/testcase/asn.1/loader/README.md)
- [Parameterized testcase source](../../../../test/testcase/asn.1/parameterized/testcase_parameterized.cpp)
- [ASN.1 runtime testcase](../../../../test/testcase/asn.1/runtime/README.md)
