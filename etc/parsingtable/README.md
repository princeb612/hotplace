# Binary parsing tables

This directory contains generated binary parsing-table artifacts used by the parser. The documented grammar coverage distinguishes two table families:

- **LALR(1):** ASN.1 notation.
- **GLR:** ASN.1 notation plus module definitions, `EXPORTS`/`IMPORTS`, parameterized constructs, information object classes, and extension markers (versions 1 and 2).

## Generation

The generator is `test/tool/makeparsingtable`. From its build/output directory, the documented commands are:

```sh
./makeparsingtable -o asn1notation.ptb
./makeparsingtable -o asn1.ptb -glr
```

The generated files are binary artifacts, not hand-maintained grammar source. For the on-disk layout, see [Binary parsing-table format](../../sdk/io/parser/parsing-table-binary-format.md).

## Test use

The repository's historical test instructions unpack/copy `parsingtable.zip` into `test/testcase/io` and `test/testcase/asn.1`. Check the active test/build setup before assuming these manual copy steps are still required in a given build.
