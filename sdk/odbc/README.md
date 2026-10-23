## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC integration

## 1. Role

The ODBC module provides a thin hotplace-oriented wrapper over the native ODBC handle and statement APIs. It is a database connectivity layer, not an ORM: connection strings, SQL statements, driver behavior, and database-specific semantics remain visible to the caller.

## 2. Data Model

The ODBC wrapper exposes native handles and result state rather than hiding them behind an ORM. The important retained objects and intermediate data are:

| Object / data | Contents | Lifetime and meaning |
|---|---|---|
| `odbc_connector` | ODBC environment handle (`HENV`) and environment configuration | Owns the environment handle; its lifetime is distinct from an individual query. |
| `odbc_query` | Connection handle (`HDBC`), statement handle (`HSTMT`), query mode, execution state, current result metadata | Governs statement cleanup and the associated connection lifetime. |
| `_field_information` | One `odbc_field` descriptor per result column | Query-owned metadata for the current result set; not a fetched row. |
| `odbc_record` | Ordered references to `odbc_field` objects | Caller-provided destination for one fetched row; it does not buffer the full result set. |
| `odbc_field` | Column ordinal/type/size plus a typed scalar, buffer, or `datetime_t` value | Represents one column's value and optional column-description metadata. |
| Diagnostic request/result | Native handle type and handle; SQLSTATE, native code, message | Request context identifies the handle; diagnostic records are collected on demand and dispatched to registered callbacks. |
| `odbc_sinker` state | Retained query reference, timeout threshold, monotonic start timestamp | Polling state only; the sinker does not own a separate connection or statement. |
| Prepared parameter input | Caller-provided data pointer and size bound to a statement | Parameter storage is not necessarily copied into durable query-owned memory; caller lifetime must cover the driver's use of it. |

`types.hpp` supplies the query-mode selector and maps native `SQLRETURN` values to hotplace `return_t`. That summary status does not preserve SQLSTATE or the full diagnostic record.

## 3. Behavior Model

The usual query path and its supporting paths are distinct:

```text
HENV / odbc_connector
        |
 connect(connection string)
        v
HDBC / odbc_query / HSTMT
        |
 SQLExecDirect or prepare -> bind -> execute
        v
result-column metadata (_field_information)
        |
 SQLFetch -> SQLGetData per column
        v
caller-owned odbc_record -> odbc_field values for one row
        |
 more() -> SQLMoreResults -> rebuild metadata for next result set

Failure detail: native handle -> SQLGetDiagRec -> registered callback(s)
Async mode: odbc_query::execute_statement() -> odbc_sinker::ready() polling / timeout
```

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
