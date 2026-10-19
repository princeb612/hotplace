## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ASN.1 loader testcase directory

## 1. Role

This directory groups testcase material for loading ASN.1 schema/module inputs.

## 2. Test model

The original directory note lists loader test sources. Detailed loader behavior and current boundaries are documented in `asn1_loader.md` and the source `testcase_loader.cpp`.

### Preserved source material

#### ASN.1 loader testcases

This directory contains the tests/samples for the corresponding hotplace module.

##### test sources

* `testcase_loader.cpp`

The loader testcase verifies both the initial file-loading/parsing step and the later semantic publication step.

```text
ASN.1 file
   |
   v
loader.load_file()
   |
   v
parse_tree
   |
   v
asn1_publisher::build()
   |
   v
asn1_runtime
```

The current test also exercises the parser's explicit intermediate stages (`to_tokens()`, `to_parsetree()`, `to_result()`), regenerated module notation, `EXPORTS`/`IMPORTS`, and `is_resolvable()` across imported module definitions.

Detailed implementation notes belong to the corresponding `sdk/io/asn.1/` documentation.

## 3. Example: source-specific testcase path

`testcase_loader.cpp` is the executable loader test source. `asn1_loader.md` describes the loader-facing behavior and result representation.

## 4. Test and verification status

### 4.1 Source-level coverage

- **O** — a dedicated loader testcase source exists.
- **△** — the directory README itself contains no assertions and is not runtime evidence.

### 4.2 Documentation and verification status

Suite-level report counts do not isolate this directory or prove the loader path was exercised on a specified OS/compiler/revision.

## 5. Relationships

- [`asn1_loader.md`](asn1_loader.md) — loader testcase notes
- [`../runtime/README.md`](../runtime/README.md) — runtime module/publisher context
- [`../../../../sdk/io/asn.1/loader/README.md`](../../../../sdk/io/asn.1/loader/README.md) — implementation-side loader

## 6. References

- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/loader/asn1_loader.md`
