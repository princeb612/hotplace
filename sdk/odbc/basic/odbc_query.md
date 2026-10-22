## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC statement execution and result traversal

## 1. Role

`odbc_query` wraps an ODBC statement handle (`HSTMT`) associated with the connection created by `odbc_connector`. It is the main API for executing SQL, binding parameters, describing result columns, fetching rows, and advancing through additional result sets.

## 2. Data Model

```text
odbc_query
  |
  +-- direct execution: SQLExecDirect
  |
  +-- prepared execution
  |     SQLPrepare
  |       -> SQLBindParameter (for each parameter)
  |       -> SQLExecute
  |
  +-- result metadata: SQLNumResultCols / SQLDescribeCol
  |
  +-- fetch: SQLFetch / SQLGetData
  |     -> odbc_record -> odbc_field[]
  |
  +-- more(): SQLMoreResults
```

The query stores the connection handle, statement handle, query mode, and a record-shaped collection of field metadata. The metadata record describes columns; each successful `fetch()` populates a separate caller-provided record with the values for one row.

## 3. Behavior Model

### Execution paths

`query()` and `execute()` format and execute a SQL string through the direct-execution path. Prepared statements use `prepare_statement()`, one or more `bind_statement_parameter()` calls, and `execute_statement()`. Parameter binding forwards the caller's buffer, C type, SQL type, and size to `SQLBindParameter`; callers remain responsible for providing suitable data storage for the parameter operation.

### Result metadata and fetching

After execution, `build_fieldinfo()` uses `SQLNumResultCols` and `SQLDescribeCol` to build column metadata. `fetch()` clears the destination record, calls `SQLFetch`, and retrieves column values with `SQLGetData`, selecting a C-side type from the SQL type. It uses a memory stream when a value needs multiple data chunks. `SQL_NO_DATA` is reported as `errorcode_t::no_data`, allowing the caller's fetch loop to stop.

`get_resultset()` reports the column count and row count returned by `SQLNumResultCols` and `SQLRowCount`; a row count of -1 is normalized to zero. `more()` calls `SQLMoreResults` and rebuilds metadata when the call succeeds.

### Closing and asynchronous mode

`close()` frees the statement handle and clears field metadata. In `async_query` mode it calls `SQLCancel` before freeing the statement. `odbc_sinker::ready()` repeatedly invokes `execute_statement()` for async work and closes the query if its timeout expires; synchronous mode is immediately considered ready.

## 4. Relationships

- [`odbc_connector.md`](odbc_connector.md) — creates the query and manages the environment/connection lifecycle
- [`odbc_record.md`](odbc_record.md) — row container populated by `fetch()`
- [`odbc_field.md`](odbc_field.md) — column values and conversions
- [`odbc_diagnose.md`](odbc_diagnose.md) — diagnostic records for failed native operations
- [`odbc_sinker.md`](odbc_sinker.md) — asynchronous readiness and timeout adapter
- [`../../types.md`](../../types.md) — query modes and ODBC return-code mapping
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample's direct execution/fetch path

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
