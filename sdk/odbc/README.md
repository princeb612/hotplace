## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC integration

## 1. Role

The ODBC module provides a thin hotplace-oriented wrapper around the native ODBC handle model. It is a database connectivity integration, not an ORM or database-specific abstraction.

## 2. Model

The public type boundary is in `types.hpp`; concrete classes are under `basic/`.

```text
odbc_connector  — environment / connection handles
      |
      v
odbc_query      — statement, parameter binding, execution
      |
      v
odbc_record    — one fetched row
      |
      v
odbc_field    — column metadata and value conversion

odbc_diagnose  — diagnostic records and callbacks
odbc_sinker    — readiness / timeout bridge for async query
```

## 3. Important behavior and lifetime

### Native handle lifecycle

The implementation uses native ODBC environment, connection, and statement handles and depends on the platform ODBC driver manager. During startup, `odbc_connector` requests connection pooling and allocates an environment configured for ODBC 3. The exact behavior still depends on the installed driver manager and the supplied connection string.

`odbc_query` is associated with a connection handle and owns a statement handle. It builds result-field metadata from `SQLNumResultCols` and `SQLDescribeCol`, and binds statement parameters through `SQLBindParameter`. Its close/destruction path closes the statement and disconnects/frees the associated connection handle; callers should not assume a query object is independent of its connection lifetime.

The build includes ANSI sources generally and Windows Unicode-specific source files on Windows. Platform-specific ODBC type widths and text types are handled in the implementation, so portability claims should be checked against the target compiler and ODBC headers.

## 4. Example from the source tests

The source sample in `test/testcase/odbc/sample.cpp` accepts a connection string (`--c`) and table name (`--t`). The flow is: parse command-line inputs, create/connect through `odbc_connector`, create a query for `select * from <table>`, execute the statement, fetch rows, and print each field name and string value. Column metadata is built from the result set before row values are read.

This is a configurable integration sample, not a self-contained test against a bundled database. Its successful execution depends on an external ODBC driver, a valid connection string, and a table accessible to that connection; the source sample alone does not establish that a live database was available during documentation.

## 5. Relationships

`odbc_connector` creates `odbc_query`; query execution produces `odbc_record` rows containing `odbc_field` values. `odbc_diagnose` reports ODBC diagnostics to registered callbacks. `odbc_sinker` adapts asynchronous query readiness and timeout handling.

## 6. References

- `types.hpp`
- `basic/README.md`
- `basic/odbc_connector.hpp/.cpp`
- `basic/odbc_query.hpp/.cpp`
- `basic/odbc_record.hpp/.cpp`
- `basic/odbc_field.hpp/.cpp`
- `test/testcase/odbc/sample.cpp`
- `CMakeLists.txt`
