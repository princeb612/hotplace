## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— ODBC integration behavior & evidence
```

# ODBC integration testcase

## 1. What

`sample.cpp` is a configurable integration sample for `sdk/odbc`. It exercises the connection → query → fetched record → field-value path and registers a callback for native ODBC diagnostics. It is not a hermetic unit test with a bundled database fixture.

## 2. How

### 2.1 Inputs and prerequisites

- `--c` supplies the ODBC connection string.
- `--t` supplies the table name used by the query.
- The caller must provide a compatible ODBC driver, connection settings, database, and table.
- If the connection string is empty, the sample leaves the test body before attempting a connection.

### 2.2 Connection, query, and row traversal

1. The sample registers `dbdiag_handler`, which logs the native error code, SQLSTATE, and diagnostic message when called.
2. It calls `odbc_connector::connect()` and records the return value.
3. On successful connection, it calls `odbc_query::query("select * from <table>")` and records the return value.
4. On successful query, it repeatedly fetches `odbc_record` objects.
5. For each record, it iterates through the fields, obtains each field name, converts the field value to a string, and logs both.
6. It calls `more()` to check for additional result sets and releases the query object after the connected path completes.

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

## 3. Evidence

### 3.1 Source-level coverage

- **O** — connection and query return values are checked and gate subsequent operations.
- **O** — fetched records and fields are traversed and displayed when the query returns rows.
- **O** — a native diagnostic callback is registered.
- **△** — there is no fixed database fixture or deterministic assertion of expected row or field values.
- **△** — the sample does not independently validate prepared-statement binding, every field conversion, asynchronous cancellation, or all diagnostic branches.
- **△** — a process that exits successfully with an empty connection string has not demonstrated a database connection.

### 3.2 Runtime verification

The user-provided Revision 1106 report for Windows 11 / MinGW64 with Application Verifier basic checks recorded:

```text
./make.sh debug odbc ctest

test-odbc  Passed  0.05 sec
100% tests passed, 0 tests failed out of 13
Total Test time: 605.59 sec
```

This verifies successful completion of the `test-odbc` CTest target in that run. It does not independently prove a live connection or validate returned values because the sample may skip connection when `--c` is omitted and contains no deterministic data assertions.

The same supplied Ubuntu 20 / Sanitizer run reported 12 passing targets but did not include `test-odbc`; it is not evidence of ODBC execution on Ubuntu. These reports were supplied by the user and were not rerun for this documentation update.

## 4. Relationships

- [`sdk/odbc/README.md`](../../../sdk/odbc/README.md) — module overview
- [`sdk/odbc/basic/README.md`](../../../sdk/odbc/basic/README.md) — concrete implementation
- [`sample.cpp`](sample.cpp) — sample source
- [`sample.hpp`](sample.hpp) — command-line option structure
- [`CMakeLists.txt`](CMakeLists.txt) — CTest target setup
- [`../test-report-status.md`](../test-report-status.md) — central report snapshot
