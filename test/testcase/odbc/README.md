## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1107
Source basis: Revision 1107
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

### Source flow

1. Register `dbdiag_handler` to log native ODBC error code, SQLSTATE, and diagnostic message.
2. Call `odbc_connector::connect()`; continue only when the return value indicates success.
3. Execute `select * from <table>` through `odbc_query::query()`; continue to row traversal only after success.
4. Fetch `odbc_record` objects, iterate their fields, obtain each field name and string-converted value, and log both.
5. Check `more()` for additional result sets and release the query object after the connected path completes.

```text
--c / --t
   |
   v
connect() -- success --> query("select * from <table>")
                                |
                             success
                                v
                          fetch(record)
                                |
                                v
                      get_field(i) / field name
                                |
                                v
                         as_string() / log
                                |
                                v
                             more()
```

### Source-level limits

- Connection and query return values gate subsequent operations.
- Records and fields are traversed when rows are returned; a diagnostic callback is registered.
- There is no fixed database fixture or deterministic assertion of expected row/field values.
- The sample does not independently validate prepared-statement binding, every field conversion, asynchronous cancellation, or every diagnostic branch.
- A successful process exit with an empty connection string does not demonstrate a database connection.

The database, driver, credentials, and table remain external prerequisites.

## 3. Evidence

The user-provided Revision 1106 Windows 11 / MinGW64 CTest report recorded `test-odbc Passed 0.05 sec` in a 13-target run. This is evidence that the target completed successfully in that run; it is **not** proof of a live database query or validated result values. The source can skip the connection when `--c` is absent and has no deterministic row-value assertions.

The reported Ubuntu 20 / Sanitizer run included 12 passing targets but did not include `test-odbc`; it is not ODBC runtime evidence. These supplied results were not rerun as part of this documentation update.

## 4. Relationships

- [`sample.cpp`](sample.cpp) — integration sample
- [`CMakeLists.txt`](CMakeLists.txt) — testcase target setup
- [`sdk/odbc/README.md`](../../../sdk/odbc/README.md) — implementation overview
- [`../test-report-status.md`](../test-report-status.md) — central report snapshot and its interpretation
