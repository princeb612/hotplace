## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ASN.1 loader testcase notes

## 1. Role

This document describes the loader testcase and the shape of its module-aware result, distinguishing current behavior from historical design intent.

## 2. Test model

The original explanation of file loading, current implementation status, and module-aware results is retained below.

### Preserved source material

### Role

`asn1_loader` is the file/stream entry point for loading ASN.1 notation source into the hotplace parser and semantic runtime flow.

The loader keeps source loading separate from parsing and semantic publication. Its current flow can be exercised in stages:

```text
ASN.1 file / memory
        |
        v
   asn1_loader
        |
        v
   asn1_parser
        |
        +-- to_tokens()
        |
        +-- to_parsetree()
        |       |
        |       v
        |   parse_tree
        |       |
        |       v
        |   to_result()
        |       |
        |       v
        +-- asn1_publisher
                |
                v
        asn1_modules
                |
                v
          module runtimes
```

The loader itself does not duplicate parser or publisher responsibilities.

### File loading

`load_file()` performs the filesystem-facing part of the operation:

1. validates the supplied output parse-tree pointer;
2. opens the ASN.1 source through `file_stream`;
3. memory-maps the source;
4. forwards the mapped buffer to the loading/parsing operation.

The parser-facing helper path can also expose the source as tokens for tests that want to inspect the intermediate parser boundary.

### Current implementation status

Revision 1097 introduced the first file-loading/parsing implementation. Revision 1099 made module imports/exports and reference resolution part of the exercised path. Revision 1100 consolidated shared ASN.1 providers under `asn1_advisor`. The current working revision renames `asn1_runtime` / `asn1_modules` to `asn1_module` / `asn1_modules`:

```text
file
  -> loader
  -> tokens
  -> parse tree
  -> asn1_advisor
       +-- publisher
       `-- parser providers
  -> module
```

The loader therefore remains a small entry point rather than becoming the owner of semantic construction.

### Module-aware result

The published runtime now contains module-level information introduced by the ASN.1 publisher, including exported and imported symbols. The publisher and parser providers are obtained from `asn1_advisor`, which is the shared ASN.1 provider for the loader/runtime path. The loader testcase verifies this with modules such as `CommonDefinitions` and `SecureMessageModule` and checks `is_resolvable()` against the resulting runtime relationships.

The testcase also regenerates ASN.1 notation from the runtime with `represent()`. This provides a useful end-to-end check that loading, parsing, publishing, module storage, and runtime representation are connected.

### Historical design note

`loader-flow.md` remains an earlier design/study sketch and should not be treated as a replacement for the current implementation record. The source-tree implementation record follows the actual loader/parser/publisher flow present in the current revision.

### Related source

- `sdk/io/asn.1/loader/asn1_loader.hpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/runtime/asn1_module.*`

### Related tests

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/`

The loader testcase intentionally separates tokenization, parse-tree construction, and semantic publication so that each boundary can be verified independently.

## 3. Example: source-specific testcase path

`testcase_loader.cpp` is the implementation-specific test source. The test suite also contains `test_asn1loader_babystep()` as a progressive loader probe; the precise assertions should be read from the source rather than inferred from this document.

## 4. Test and verification status

### 4.1 Source-level coverage

- **O** — dedicated loader test source is present.
- **△** — a documented loader flow is not proof that all malformed-input, multi-module, and dependency-resolution cases are asserted.

### 4.2 Documentation and verification status

The supplied ASN.1 report is suite-level and has no per-function mapping, OS/compiler/build configuration, or source revision. No tests were run for this documentation update.

## 5. Relationships

- [`README.md`](README.md) — loader testcase directory
- [`../runtime/asn1_module.md`](../runtime/asn1_module.md) — module representation
- [`../../../../sdk/io/asn.1/loader/asn1_loader.md`](../../../../sdk/io/asn.1/loader/asn1_loader.md) — loader implementation

## 6. References

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/loader/asn1_loader.hpp`

## 7. Development Notes (for maintainer review)

The original document has a `Historical design note`. It is retained in the preserved source material below and should be reviewed as historical intent, not assumed to describe the current implementation.
