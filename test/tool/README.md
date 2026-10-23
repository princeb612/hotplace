## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: parser-table build tool
```

# Test-supporting tools

## 1. Role

`test/tool` contains build-support utilities that prepare resources consumed by the parser runtime and its testcase groups. The current tool, `makeparsingtable`, generates binary parsing-table files from parser configurations. It is not itself the parser runtime: generation and parsing are separate stages with different responsibilities.

## 2. Tool Model

The overall relationship is split into a **tool role** that builds a binary parsing table and a **parser role** that imports that table and uses it to parse input.

```text
Tool role
  parser CFG
      │ build
      ▼
  binary parsing table (.ptb)
      │ packaged as
      ▼
  parsingtable.zip
      │ extracted by etc/parsingtable/CMakeLists.txt
      ▼
  build-tree resources for parser / ASN.1 testcases


Parser role
  import binary parsing table
      │
      ▼
  parser CFG / runtime table state
      │ parse input
      ▼
  parse tree
```

`makeparsingtable` selects a parser configuration, ensures the parser is ready, learns its table representation, and serializes it to a `.ptb` file. The current build rule generates two variants:

- `asn1notation.ptb` — the default accessor selects the ASN.1 notation parser.
- `asn1.ptb` — the `-glr` option selects the ASN.1 parser built for GLR.

The generator's CMake post-build rule is conditional: it runs for GNU C++ on Windows, the documented MinGW64 development path. That rule packages the generated files as `parsingtable.zip`. Separately, `etc/parsingtable/CMakeLists.txt` extracts the checked-in archive into the configured build-tree testcase directories. Archive extraction does not regenerate the parser tables, and the generator is not run on every platform or every build.

## 3. Relationships

- [makeparsingtable implementation and build rule](makeparsingtable/README.md) — command-line options, parser selection, table construction, and serialization.
- [Parser implementation](../../sdk/io/parser/README.md) — importing the binary table and parsing input.
- [ASN.1 implementation](../../sdk/io/asn.1/README.md) — grammar and higher-level parser consumer.
- [Stored parsing-table artifacts](../../etc/parsingtable/README.md) — checked-in archive and build-tree extraction.
- [Parser testcase group](../testcase/io/parser/README.md) and [ASN.1 testcase group](../testcase/asn.1/README.md) — downstream consumers of the generated resources.
- [Test area](../README.md) — distinction between testcase groups, integration applets, and build-support tools.
- `test/tool/CMakeLists.txt` — registers the tool subdirectory.
