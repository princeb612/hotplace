## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— ODBC testcase scope, execution & evidence
```

# ODBC testcase directory

## 1. What

This directory contains the configurable `test-odbc` integration sample for `sdk/odbc`. It demonstrates the connection-to-row traversal path when supplied with a usable ODBC connection and table. It does not provision a database or validate a fixed result set.

## 2. How

- `test/testcase/CMakeLists.txt` adds this directory only when `SUPPORT_ODBC` is enabled.
- `CMakeLists.txt` defines the `odbc` module and registers it through the shared `maketest(...)` helper.
- `sample.cpp` accepts `--c` for the connection string and `--t` for the table name.
- With a non-empty connection string, the sample calls `odbc_connector::connect()`, executes `select * from <table>`, fetches records, and logs each field name and string value. It registers `dbdiag_handler` to log native error details.
- If `--c` is absent or empty, the sample exits its test body before connecting. The database, driver, credentials, and table are external prerequisites.

The detailed source path and its limits are recorded in [ODBC integration testcase](testcase_odbc.md).

## 3. Evidence

The user-provided Revision 1106 Windows 11 / MinGW64 CTest report recorded `test-odbc Passed 0.05 sec` in a 13-target run. This is evidence that the target completed successfully in that run; it is **not** proof of a live database query or validated result values. The source can skip the connection when `--c` is absent and has no deterministic row-value assertions.

The reported Ubuntu 20 / Sanitizer run included 12 passing targets but did not include `test-odbc`; it is not ODBC runtime evidence. These supplied results were not rerun as part of this documentation update.

## 4. Relationships

- [`testcase_odbc.md`](testcase_odbc.md) — detailed source-level coverage and verification interpretation
- [`sample.cpp`](sample.cpp) — integration sample
- [`CMakeLists.txt`](CMakeLists.txt) — testcase target setup
- [`sdk/odbc/README.md`](../../../sdk/odbc/README.md) — implementation overview
- [`../test-report-status.md`](../test-report-status.md) — central report snapshot and its interpretation

## 5. References

- `sample.cpp`
- `sample.hpp`
- `CMakeLists.txt`
- [ODBC integration testcase](testcase_odbc.md)
