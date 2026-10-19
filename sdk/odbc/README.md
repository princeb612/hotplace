## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
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

The implementation uses native ODBC handles and depends on the platform ODBC library. The build includes ANSI sources generally and Windows Unicode-specific source files when building on Windows. The connector enables connection pooling and configures ODBC 3 during startup.

## 4. Example from the source tests

The source testcase in `test/testcase/odbc/sample.cpp` accepts a connection string (`--c`) and table name (`--t`), connects, issues `select * from <table>`, fetches rows, and prints each field name and string value. This is a configurable integration sample, not a self-contained test against a bundled database.

## 5. Relationships

`odbc_connector` creates `odbc_query`; query execution produces `odbc_record` rows containing `odbc_field` values. `odbc_diagnose` reports ODBC diagnostics to registered callbacks. `odbc_sinker` adapts asynchronous query readiness and timeout handling.

## 6. References

- `types.hpp`
- `basic/README.md`
- `test/testcase/odbc/sample.cpp`
- `CMakeLists.txt`
