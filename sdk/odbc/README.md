## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC integration

## 1. Role

The ODBC module provides a thin hotplace-oriented wrapper over the native ODBC handle and statement APIs. It is a database connectivity layer, not an ORM: connection strings, SQL statements, driver behavior, and database-specific semantics remain visible to the caller.

## 2. Data Model

The public boundary in `types.hpp` defines the query mode, shared class declarations, and conversion from `SQLRETURN` to hotplace `return_t`. Concrete wrappers are implemented under `basic/`.

```text
odbc_connector
  environment (HENV) / connection (HDBC)
       |
       v
odbc_query
  statement (HSTMT), execution and result metadata
       |
       v
odbc_record
  one fetched row
       |
       v
odbc_field
  column metadata and retrieved value

Cross-cutting:
  odbc_diagnose  -> SQL diagnostic records -> registered callbacks
  odbc_sinker    -> readiness / timeout handling for async query
```

The main path is connector → query → record → field. Diagnostics and asynchronous readiness are supporting mechanisms rather than additional steps in every query.

## 3. Behavior Model

### Connection and statement lifecycle

`odbc_connector` initializes an ODBC environment, requests connection pooling, selects ODBC 3, and creates a query associated with a connection handle. `odbc_query` owns a statement handle. Its destructor closes the statement and disconnects/frees the associated connection; a query therefore should not be treated as independent of its connection lifecycle.

### Execution and result traversal

Direct execution uses `SQLExecDirect`. Prepared execution follows `SQLPrepare`, `SQLBindParameter`, and `SQLExecute`. Result metadata is collected with `SQLNumResultCols` and `SQLDescribeCol`; fetching uses `SQLFetch` and `SQLGetData`. The result is exposed as `odbc_record` rows containing `odbc_field` values. `more()` advances to subsequent result sets with `SQLMoreResults`.

### Errors and platform integration

Native return codes are converted into coarse hotplace error categories by `error_traits<SQLRETURN, odbc_category>`. Detailed SQLSTATE, native error code, and message are retrieved separately through `odbc_diagnose`. The build links the platform ODBC library and includes Windows Unicode-specific sources selected by the module's CMake configuration. Actual connectivity and data behavior depend on the installed driver manager, driver, connection string, and database.

## 4. Relationships

- [`types.md`](types.md) — shared ODBC types, query modes, and return-code conversion
- [`basic/README.md`](basic/README.md) — concrete wrapper classes
- [`basic/odbc_connector.md`](basic/odbc_connector.md) — environment and connection lifecycle
- [`basic/odbc_query.md`](basic/odbc_query.md) — statement execution and result traversal
- [`basic/odbc_record.md`](basic/odbc_record.md) and [`basic/odbc_field.md`](basic/odbc_field.md) — row and column representation
- [`basic/odbc_diagnose.md`](basic/odbc_diagnose.md) — diagnostic callbacks
- [`basic/odbc_sinker.md`](basic/odbc_sinker.md) — async readiness and timeout bridge
- [`test/testcase/odbc/testcase_odbc.md`](../../test/testcase/odbc/testcase_odbc.md) — sample behavior and verification limits

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
