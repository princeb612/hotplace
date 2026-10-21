## Publication

```text
hotplace source tree
Edition 1 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC integration testcase

## 1. Role

`sample.cpp` is an integration sample for `sdk/odbc`. It exercises the caller-configured connection → query → row → field path and reports ODBC diagnostics through a registered callback. It is not a hermetic unit test.

## 2. Test model

The sample parses `--c` (connection string) and `--t` (table name), attempts connection, executes a formatted `select * from <table>`, fetches rows, and prints column names and string values. The caller must supply an appropriate driver, credentials, database, and table.

## 3. Example: connection and row traversal

The source flow is `odbc_connector::connect()` → `odbc_query::query()` → repeated `fetch()` → `odbc_record::get_field()` → `odbc_field::as_string()`. The sample checks success returns before proceeding and releases the query after result traversal.

## 4. Test and verification status

### 4.1 Source-level coverage

- **O** — connection success/failure gates control whether query execution proceeds.
- **O** — query success/failure gates control whether fetching proceeds.
- **O** — returned rows and fields are traversed and displayed.
- **△** — the sample has no fixed database fixture or deterministic assertions over returned values.
- **△** — prepared statement parameter binding, every field conversion, asynchronous cancellation, and all diagnostic branches are not independently exercised by this sample.

### 4.2 Documentation and verification status

The supplied `test/testcase/odbc/report` contains `pass 0` and no classified case counts; the central [Test Report Snapshot](../test-report-status.md) records this as an empty/unclassified report rather than a successful live integration run. It does not establish that a database connection succeeded. The report does not identify connection configuration, driver, database, OS/compiler, or tested source revision. The documentation basis is Revision 1105, distinct from the unverified report-run revision. No test was executed as part of this documentation update.

## 5. Relationships

- [`sdk/odbc/README.md`](../../../sdk/odbc/README.md) — module overview
- [`sdk/odbc/basic/README.md`](../../../sdk/odbc/basic/README.md) — concrete implementation
- [`sample.cpp`](sample.cpp) — testcase source
- [`CMakeLists.txt`](CMakeLists.txt) — testcase target setup

## 6. References

- `test/testcase/odbc/sample.cpp`
- `test/testcase/odbc/sample.hpp`
- `test/testcase/odbc/CMakeLists.txt`
- `sdk/odbc/CMakeLists.txt`
