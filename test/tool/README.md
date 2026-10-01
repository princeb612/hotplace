# test/tool

`test/tool` contains utilities that prepare resources used by the test suite rather than ordinary testcase executables.

## makeparsingtable

The current tool is `makeparsingtable`. It builds parser-table resources from the grammar definitions used by the project.

Its post-build step generates two parser tables:

```text
makeparsingtable
      │
      ├── asn1notation.ptb
      └── asn1.ptb  (--glr)
             │
             ▼
       parsingtable.zip
```

The generated archive is the resource consumed by the parser build/test workflow. This is the same parsing-table generation path documented under `sdk/io/parser`.

## Build relationship

```text
test/tool/CMakeLists.txt
        │
        ▼
  makeparsingtable
        │
        ▼
 parser table resources
        │
        ▼
 sdk/io/parser tests
```

This directory is therefore a **test-supporting build tool**, not another layer of the SDK itself.

## Related documentation

- [`test`](../README.md)
- [`testcase`](../testcase/README.md)
- [`sdk/io/parser`](../../sdk/io/parser/README.md)
