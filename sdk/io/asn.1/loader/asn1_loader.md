# Developer Notes — ASN.1 Loader

## Role

`asn1_loader` is the file/stream entry point for loading ASN.1 notation source into the hotplace parser and semantic runtime flow. This file remains a Developer Notes document; its explanatory style is intentionally preserved rather than converted to the standardized source-tree template.

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1107
Source basis: Revision 1107
Developer Notes — ASN.1 Loader
```

The loader keeps source acquisition separate from tokenization, grammar parsing, and semantic publication. Its stages can be exercised independently:

```text
ASN.1 file / memory
        |
        v
   asn1_loader
        |
        v
   asn1_parser
        |
        +-- to_tokens() ----------> parser_token[]
        |
        +-- to_parsetree() -------> parse_tree
        |                               |
        |                               v
        +-- to_result() ----------> asn1_publisher
                                        |
                                        v
                                asn1_build_resultset
                                        |
                                        v
                               asn1_module / asn1_modules
                                        |
                                        v
                               import/reference resolution
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

The implementation history is recorded in `CHANGELOG`; the current boundary is that the loader coordinates parser and publisher components rather than owning semantic construction. Shared ASN.1 parser/publisher providers are obtained through `asn1_advisor`. Current runtime names are `asn1_module` and `asn1_modules`; `asn1_module_context` and earlier `asn1_runtime` names belong to historical revisions.

```text
file / memory
  -> loader
  -> tokens
  -> parse tree
  -> asn1_advisor
       +-- parser providers
       `-- publisher
  -> module / module registry
```

## Module-aware result

The published runtime contains module-level information including exported and imported symbols. The loader testcase uses modules such as `CommonDefinitions` and `SecureMessageModule`, checks `is_resolvable()` against the resulting runtime relationships, and regenerates ASN.1 notation through `represent()`.

This is an integrated source path connecting loading, parsing, publishing, module storage, and runtime representation. It should not be generalized to complete support for every ASN.1 notation feature.

## Historical design note

`loader-flow.md` remains an earlier design/study sketch and should not be treated as a replacement for the current implementation record. The current implementation path is described by the loader, parser adapter, publisher, and module source together.

## Related source

- `sdk/io/asn.1/loader/asn1_loader.hpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/runtime/asn1_module.*`
- `sdk/io/asn.1/asn1_advisor.hpp`

## Related tests

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`

The loader testcase intentionally separates tokenization, parse-tree construction, and semantic publication so that each boundary can be inspected independently.
