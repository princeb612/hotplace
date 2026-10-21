## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```

# ASN.1 loader testcase directory

## 1. Role

This directory contains the focused testcase for loading ASN.1 module source and checking the boundary between parsing, semantic publishing, and module reference resolution.

## 2. Test model

`testcase_loader.cpp` exercises more than opening a file. Its path includes the loader's explicit intermediate stages (`to_tokens()`, `to_parsetree()`, and `to_result()`), then the shared `asn1_publisher::build()` path that constructs runtime module information.

```text
ASN.1 source file
       |
       v
asn1_loader::load_file()
       |
       +--> tokens / parse tree / loader result
                         |
                         v
                asn1_publisher::build()
                         |
                         v
                 asn1_module(s)
                         |
                         v
           imported symbol lookup / is_resolvable()
```

## 3. Example: imported-symbol resolution

In `testcase_loader.cpp`, follow the loaded module through the intermediate parser representations and into publisher construction. The testcase also inspects regenerated module notation, `EXPORTS`/`IMPORTS`, and `is_resolvable()` across imported module definitions. This makes the module lookup boundary visible: parsing an import clause is not the same as proving the referenced symbol can be resolved.

## 4. Test and verification status

### 4.1 Source-level coverage

- **Present:** a dedicated loader testcase source covers loading/parsing stages and semantic publication.
- **Present:** imported module and symbol resolvability are inspected in the source path.
- **Boundary:** the existence of the testcase does not prove that every module syntax form, import failure, malformed file, or runtime environment is covered.

### 4.2 Documentation and verification status

Suite-level ASN.1 report totals do not isolate this directory or prove that the loader path ran on a specified OS/compiler/source revision. The latest documented aggregate context is Revision 1104 · MinGW64/GCC · CTest; the source documentation basis is Revision 1105. No tests were run as part of this documentation update.

## 5. Relationships

- [Loader testcase notes](asn1_loader.md)
- [Runtime module/publisher tests](../runtime/README.md)
- [Implementation-side loader](../../../../sdk/io/asn.1/loader/README.md)
- [ASN.1 implementation overview](../../../../sdk/io/asn.1/README.md)

## 6. References

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/asn1_loader.md`
- `sdk/io/asn.1/loader/asn1_loader.cpp/.hpp`
- `sdk/io/asn.1/runtime/asn1_publisher.cpp`
