## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Loader

## 1. Role

`asn1_loader` is the file/stream entry point for loading ASN.1 notation source into the hotplace parser and semantic runtime flow.

## 2. Model

### File loading

`load_file()` performs the filesystem-facing part of the operation:

1. validates the supplied output parse-tree pointer;
2. opens the ASN.1 source through `file_stream`;
3. memory-maps the source;
4. forwards the mapped buffer to the loading/parsing operation.

The parser-facing helper path can also expose the source as tokens for tests that want to inspect the intermediate parser boundary.

### Module-aware result

The published runtime now contains module-level information introduced by the ASN.1 publisher, including exported and imported symbols. The publisher and parser providers are obtained from `asn1_advisor`, which is the shared ASN.1 provider for the loader/runtime path. The loader testcase verifies this with modules such as `CommonDefinitions` and `SecureMessageModule` and checks `is_resolvable()` against the resulting runtime relationships.

The testcase also regenerates ASN.1 notation from the runtime with `represent()`. This provides a useful end-to-end check that loading, parsing, publishing, module storage, and runtime representation are connected.

## 3. Important behavior and lifetime

### Current implementation status

Revision 1097 introduced the first file-loading/parsing implementation. Revision 1099 made module imports/exports and reference resolution part of the exercised path. Revision 1100 consolidated shared ASN.1 providers under `asn1_advisor`. The current working revision renames `asn1_runtime` and `asn1_modules` to `asn1_module` and `asn1_modules`:

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

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/`

The loader testcase intentionally separates tokenization, parse-tree construction, and semantic publication so that each boundary can be verified independently.

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

### Related source

- `sdk/io/asn.1/loader/asn1_loader.hpp`
- `sdk/io/asn.1/loader/asn1_loader.cpp`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/runtime/asn1_module.*`

## 7. Development Notes (for maintainer review)

### Historical design note

`loader-flow.md` remains an earlier design/study sketch and should not be treated as a replacement for the current implementation record. The source-tree implementation record follows the actual loader/parser/publisher flow present in the current revision.
