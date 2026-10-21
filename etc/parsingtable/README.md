## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: generated parser-table artifacts and build distribution
```

# Binary parsing tables

## 1. Role

This directory stores generated binary parsing-table artifacts consumed by the parser and ASN.1 test/build paths. The `.ptb` tables are generated outputs, not hand-maintained grammar source.

## 2. Model

The documented grammar coverage distinguishes two table families:

- **LALR(1):** ASN.1 notation.
- **GLR:** ASN.1 notation plus module definitions, `EXPORTS`/`IMPORTS`, parameterized constructs, information object classes, and extension markers (versions 1 and 2).

The generator lives under `test/tool/makeparsingtable`; the binary format is documented in [Binary parsing-table format](../../sdk/io/parser/parsing-table-binary-format.md).

## 3. Important behavior and lifetime

The build flow has two related but distinct operations:

1. The generator's CMake post-build path can create `asn1notation.ptb` and `asn1.ptb` and package them into `parsingtable.zip` for the configured MinGW64/GNU-on-Windows path.
2. `etc/parsingtable/CMakeLists.txt` unpacks the stored `parsingtable.zip` into the build-tree `test/testcase/io` and `test/testcase/asn.1` directories.

Do not assume every platform regenerates the tables during every build. Confirm the active CMake configuration and archive contents when diagnosing missing or stale parser resources.

## 4. Example from the source build

From the generator's build/output directory, the documented generator commands are:

```sh
./makeparsingtable -o asn1notation.ptb
./makeparsingtable -o asn1.ptb -glr
```

The resulting artifacts are then packaged/copied according to the build configuration. These commands document the generation path; they were not run during this documentation update.

## 5. Relationships

- `sdk/io/parser/` — parser runtime and binary table format.
- `sdk/io/asn.1/` — ASN.1 parser/loader/runtime consumers.
- `test/tool/makeparsingtable/` — table generation utility.
- `test/testcase/io/parser/` and `test/testcase/asn.1/` — test consumers.

## 6. References

- [Binary parsing-table format](../../sdk/io/parser/parsing-table-binary-format.md)
- `CMakeLists.txt`
- `test/tool/makeparsingtable/CMakeLists.txt`
- `test/tool/makeparsingtable/`
