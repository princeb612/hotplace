## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: binary parser-table artifact and build distribution
```

# Binary parsing tables

## 1. Role

`etc/parsingtable/` stores the packaged binary parsing-table artifact consumed by parser and ASN.1 test/build paths. The `.ptb` tables are generated outputs, not hand-maintained grammar source.

## 2. Data Model

The packaged archive is `parsingtable.zip`. Its documented table families are:

- **LALR(1):** ASN.1 notation.
- **GLR:** ASN.1 notation plus module definitions, `EXPORTS`/`IMPORTS`, parameterized constructs, information object classes, and extension markers (versions 1 and 2).

The generator is maintained under `test/tool/makeparsingtable/`; the binary layout is described in `sdk/io/parser/parsing-table-binary-format.md`. The archive is a distribution artifact; it is not the grammar source and is not itself the parser runtime state.

## 3. Behavior Model

The resource lifecycle has separate generation, packaging, and extraction stages:

```text
grammar / parser configuration
       │
       ▼
test/tool/makeparsingtable
       │ generate
       ▼
asn1notation.ptb + asn1.ptb
       │ package (conditional build path)
       ▼
parsingtable.zip
       │ unzip by etc/parsingtable/CMakeLists.txt
       ├───────────────────────┐
       ▼                       ▼
test/testcase/io/         test/testcase/asn.1/
build-tree tables         build-tree tables
```

The generator's CMake post-build path can create `asn1notation.ptb` and `asn1.ptb` and package them into `parsingtable.zip` for the GNU-on-Windows path used by the documented MinGW64 setup. `etc/parsingtable/CMakeLists.txt` unpacks the stored archive into build-tree testcase directories; it does not regenerate the tables.

Do not assume every platform regenerates the tables during every build. When diagnosing missing or stale parser resources, inspect the active CMake configuration and the archive contents. This documentation update did not execute the generator or verify a newly generated archive.

## 4. Relationships

- `sdk/io/parser/` — parser runtime and binary table format.
- `sdk/io/asn.1/` — ASN.1 parser/loader/runtime consumers.
- `test/tool/makeparsingtable/` — table generation utility.
- `test/testcase/io/parser/` and `test/testcase/asn.1/` — test consumers.
- [Repository resource map](../README.md) — relationship to other repository-managed resources.
