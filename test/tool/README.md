## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: test-supporting build tools
```

# Test-supporting tools

## 1. Role

`test/tool` contains utilities that prepare resources used by the test suite rather than ordinary testcase executables. The current important tool is `makeparsingtable`.

## 2. Model

```text
grammar definitions
       │
       ▼
makeparsingtable
       ├── asn1notation.ptb
       └── asn1.ptb (-glr)
                 │
                 ▼
          parsingtable.zip
                 │
                 ▼
    etc/parsingtable / parser tests
```

The generated binary tables are test/build resources, not hand-maintained grammar source.

## 3. Example from the build

The `makeparsingtable` CMake post-build path generates `asn1notation.ptb` and `asn1.ptb` and packages them into `parsingtable.zip` under its configured GNU-on-Windows (MinGW64) path. The repository's `etc/parsingtable/CMakeLists.txt` separately unpacks the stored archive into parser and ASN.1 testcase build directories. Do not assume every platform regenerates the archive during every build.

## 4. Test and verification status

### 4.1 Source-level coverage

This is a resource-generation tool, not a testcase group. Its output should be checked through generation success and the downstream parser tests that consume the tables.

### 4.2 Documentation and verification status

The generation commands and CMake path are documented here; they were not run during this documentation update.

## 5. Relationships

- `sdk/io/parser/` — parser runtime and binary parsing-table format.
- `etc/parsingtable/` — stored table archive and build-tree distribution.
- `test/testcase/io/parser/` and `test/testcase/asn.1/` — downstream consumers.

## 6. References

- [Overall test area](../README.md)
- [Testcase tree](../testcase/README.md)
- [Binary parsing tables](../../etc/parsingtable/README.md)
- `test/tool/makeparsingtable/CMakeLists.txt`
