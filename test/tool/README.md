## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: test-supporting build tools
```

# Test-supporting tools

## 1. Role

`test/tool` contains build-support utilities that prepare resources consumed by tests. It is distinct from `test/testcase`, which builds executable test groups, and `test/applet`, which contains runnable integration examples. The current subdirectory is `makeparsingtable`, a command-line generator for the binary parser-table resources used by parser-related tests.

## 2. Model

```text
sdk/io/parser + ASN.1 grammar builders
                 │
                 ▼
        makeparsingtable
          ├─ default: ASN.1 notation parser
          │            └─ asn1notation.ptb
          └─ -glr: ASN.1 parser
                       └─ asn1.ptb
                 │
                 ▼
          parsingtable.zip
                 │
                 ▼
       etc/parsingtable/CMakeLists.txt
          ├─ test/testcase/io/
          └─ test/testcase/asn.1/
```

The `.ptb` files are generated artifacts, not hand-maintained grammar source. The generator's CMake post-build command is conditional: it runs for GNU C++ on Windows (the documented MinGW64 development path). Separately, `etc/parsingtable/CMakeLists.txt` unpacks the checked-in archive into the configured build-tree testcase directories. These are different operations; the archive is not regenerated on every platform or every build.

## 3. Example from the source build

From the generator's output directory, the two commands used by the CMake post-build rule are:

```sh
./makeparsingtable -o asn1notation.ptb
./makeparsingtable -o asn1.ptb -glr
```

The first uses the default parser type, which selects the ASN.1 notation parser. The second selects the GLR parser with `-glr`. In both cases, `-o` is required to name the output file. The CMake rule then packages both files as `parsingtable.zip`.

## 4. Test and verification status

### 4.1 Source-level coverage

This is a resource-generation tool, not a CTest testcase group. Its relevant checks are whether parser-table generation succeeds, whether the archive contains the expected artifacts, and whether downstream parser/ASN.1 tests can consume them. The presence of the generator and its build rule does not by itself prove that generation was run successfully on every supported platform.

### 4.2 Documentation and verification status

The generation path is documented from `sample.cpp`, the tool's `CMakeLists.txt`, and `etc/parsingtable/CMakeLists.txt`. Generation and downstream tests were not run as part of this documentation update.

## 5. Relationships

- [Parser implementation](../../sdk/io/parser/README.md) — parser construction, table serialization, and execution.
- [ASN.1 implementation](../../sdk/io/asn.1/README.md) — grammar and higher-level parser consumer.
- [Stored parsing-table artifacts](../../etc/parsingtable/README.md) — checked-in archive and build-tree extraction.
- [Parser testcase group](../testcase/io/parser/README.md) and [ASN.1 testcase group](../testcase/asn.1/README.md) — downstream consumers of the generated resources.
- [Test area](../README.md) — overall distinction between testcases, applets, and tools.

## 6. References

- `test/tool/CMakeLists.txt` — registers the tool subdirectory.
- [`makeparsingtable` implementation and build rule](makeparsingtable/README.md) — command-line behavior and conditional generation path.
