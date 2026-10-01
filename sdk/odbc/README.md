### ODBC integration

This directory contains the ODBC integration layer used by hotplace when database connectivity is required.

The public ODBC types are defined in `types.hpp`; the concrete implementation is under `basic/`. The implementation is intentionally a thin hotplace-oriented wrapper around the native ODBC handle model rather than a database-specific abstraction.

#### Main flow

```text
connection string
       |
       v
odbc_connector
       |
       +---- HENV / HDBC
       |
       v
  odbc_query
       |
       +---- SQLExecDirect / SQLPrepare + SQLBindParameter + SQLExecute
       |
       v
  result set
       |
       +---- odbc_record
       |        |
       |        +---- odbc_field
       |
       +---- SQLMoreResults

errors from ODBC handles
       |
       v
odbc_diagnose
```

#### Documents

- [basic/odbc_connector.md](basic/odbc_connector.md) — environment, connection and lifecycle
- [basic/odbc_query.md](basic/odbc_query.md) — statement execution, binding and result traversal
- [basic/odbc_record.md](basic/odbc_record.md) — row/field collection
- [basic/odbc_field.md](basic/odbc_field.md) — field metadata and value conversion
- [basic/odbc_diagnose.md](basic/odbc_diagnose.md) — SQL diagnostic records and application callbacks
- [basic/odbc_sinker.md](basic/odbc_sinker.md) — query readiness/sink integration

The test/sample under `test/testcase/odbc` demonstrates the intended connector → query → record → field path with a caller-supplied connection string and table name.
