## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC statement execution and result traversal

## 1. Role

`odbc_query` wraps an ODBC statement handle (`HSTMT`) associated with the connection created by `odbc_connector`. It is the main API for executing SQL, binding parameters, describing result columns, fetching rows, and advancing through additional result sets.

## 2. Data Model

```text
odbc_query
  +-- _dbc_handle : HDBC
  +-- _stmt_handle : HSTMT
  +-- _sql_mode : sync_query | async_query
  +-- _field_information : odbc_record
  |       +-- odbc_field[] (column descriptors)
  +-- current execution/result status
  +-- current result-set metadata
  +-- caller-provided odbc_record
          +-- odbc_field[] (values for one row)
```

_field_information represents column metadata for the current result set, not a fetched row. Each metadata field can carry a column ordinal, SQL/data type, reported size/name, and optional field-info reference. The caller-provided record has the same container type but a different role: it holds the values for one row.

Prepared-statement parameters are bound using caller-provided data pointers and sizes. The query does not necessarily make a durable copy of each parameter buffer, so the caller must preserve the bound storage for as long as the ODBC operation requires it. The native statement handle and execution mode are query state; they are not row data.

## 3. Behavior Model

### SQL execution

```text
query()/execute() ------------------> SQLExecDirect
prepare_statement() -> SQLPrepare
                         |
                         v
              bind_statement_parameter()
                         |
                         v
                   SQLBindParameter
                         |
                         v
                execute_statement()
                         |
                         v
                     SQLExecute
```

Successful execution calls `build_fieldinfo()`. That routine calls `SQLNumResultCols`, then walks one-based ODBC column ordinals with `SQLDescribeCol` and stores the descriptions in `_field_information`. `SQL_SUCCESS_WITH_INFO` is treated as successful native completion by the shared return conversion, although diagnostic detail is separate.

### Fetching a row

1. `fetch(record)` rejects a null destination and clears the destination record before fetching.
2. `SQLFetch` advances the native cursor. `SQL_NO_DATA` becomes `errorcode_t::no_data`; other unsuccessful results become a fetch failure.
3. For each described column, the query selects a C retrieval type based on the SQL type (character/wide character, binary, integer, floating point, bit, or date/time).
4. `SQLGetData` reads the column. When data is returned in multiple chunks, the query accumulates chunks in `basic_stream` before constructing the field.
5. A new `odbc_field` is appended to the caller's record. The resulting record represents only this fetched row.

### Result traversal and close

`get_resultset()` queries `SQLNumResultCols` and `SQLRowCount`; it initializes output values to zero and normalizes row count `-1` to zero. `more()` invokes `SQLMoreResults`; on success it clears and rebuilds metadata for the next result. `close()` cancels asynchronous execution when applicable, frees `HSTMT`, and clears metadata. The query destructor then disconnects/frees its associated `HDBC`.

### Asynchronous polling

For `async_query`, `odbc_sinker::ready()` repeatedly calls `execute_statement()`. A `busy` result causes elapsed monotonic time to be checked; once it exceeds the configured timeout, the sinker returns timeout and closes the query. Synchronous mode returns ready immediately. This adapter does not itself schedule threads or make a synchronous driver operation asynchronous.

## 4. Relationships
- [`odbc_connector.md`](odbc_connector.md) — creates the query and manages the environment/connection lifecycle
- [`odbc_record.md`](odbc_record.md) — row container populated by `fetch()`
- [`odbc_field.md`](odbc_field.md) — column values and conversions
- [`odbc_diagnose.md`](odbc_diagnose.md) — diagnostic records for failed native operations
- [`odbc_sinker.md`](odbc_sinker.md) — asynchronous readiness and timeout adapter
- [`../../types.md`](../../types.md) — query modes and ODBC return-code mapping
- [`../../../test/testcase/odbc/README.md`](../../../test/testcase/odbc/README.md) — sample's direct execution/fetch path

## 5. References
- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
