## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC testcase directory

## 1. Role

This directory contains the configurable ODBC integration sample for `sdk/odbc`. The detailed source-level coverage and verification limits are documented in [`testcase_odbc.md`](testcase_odbc.md).

## 2. Test model

`sample.cpp` accepts a caller-supplied connection string and table name; it does not provision a database fixture.

## 3. Example: ODBC integration sample

See [`testcase_odbc.md`](testcase_odbc.md) for the connection-to-row traversal.

## 4. Test and verification status

### 4.1 Source-level coverage

The sample covers the integration path only when supplied with a valid ODBC driver, connection string, and table. It does not provide deterministic assertions over returned database values.

### 4.2 Documentation and verification status

The supplied report records `pass 0` with no classified cases. Successful live database execution is not established by that report.

## 5. Relationships

- [`testcase_odbc.md`](testcase_odbc.md) — detailed sample analysis
- [`sample.cpp`](sample.cpp) — testcase source
- [`CMakeLists.txt`](CMakeLists.txt) — target setup
- [`sdk/odbc/README.md`](../../../sdk/odbc/README.md) — implementation overview

## 6. References

- `test/testcase/odbc/sample.cpp`
- `test/testcase/odbc/sample.hpp`
- `test/testcase/odbc/CMakeLists.txt`
