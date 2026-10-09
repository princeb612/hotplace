# ASN.1 Loader

## Role

`asn1_loader` is the file/stream entry point for loading ASN.1 notation source into the hotplace parser and semantic runtime flow.

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1102
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

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
        asn1_module_context
                |
                v
          module runtimes
```

The loader itself does not duplicate parser or publisher responsibilities.

## File loading

`load_file()` performs the filesystem-facing part of the operation:

1. validates the supplied output parse-tree pointer;
2. opens the ASN.1 source through `file_stream`;
3. memory-maps the source;
4. forwards the mapped buffer to the loading/parsing operation.

The parser-facing helper path can also expose the source as tokens for tests that want to inspect the intermediate parser boundary.

## Current implementation status

Revision 1097 introduced the first file-loading/parsing implementation. Revision 1099 made module imports/exports and reference resolution part of the exercised path. Revision 1100 consolidated shared ASN.1 providers under `asn1_advisor`. The current working revision renames `asn1_runtime` and `asn1_runtime_context` to `asn1_module` and `asn1_module_context`:

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

## Module-aware result

The published runtime now contains module-level information introduced by the ASN.1 publisher, including exported and imported symbols. The publisher and parser providers are obtained from `asn1_advisor`, which is the shared ASN.1 provider for the loader/runtime path. The loader testcase verifies this with modules such as `CommonDefinitions` and `SecureMessageModule` and checks `is_resolvable()` against the resulting runtime relationships.

The testcase also regenerates ASN.1 notation from the runtime with `represent()`. This provides a useful end-to-end check that loading, parsing, publishing, module storage, and runtime representation are connected.

## Historical design note

`loader-flow.md` remains an earlier design/study sketch and should not be treated as a replacement for the current implementation record. The source-tree implementation record follows the actual loader/parser/publisher flow present in the current revision.

## Related source

- `sdk/io/asn.1/loader/asn1_loader.hpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/runtime/asn1_module.*`

## Related tests

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/`

The loader testcase intentionally separates tokenization, parse-tree construction, and semantic publication so that each boundary can be verified independently.
