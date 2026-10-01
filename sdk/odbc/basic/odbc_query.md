# odbc_query

`odbc_query` wraps an ODBC statement handle (`HSTMT`) and is the main execution/result-set object returned by `odbc_connector`.

## Execution model

```text
odbc_query
   |
   +--> query()/execute()
   |       |
   |       +--> SQLExecDirect
   |
   +--> prepare_statement()
   |       |
   |       +--> SQLPrepare
   |       +--> bind_statement_parameter()
   |       |       |
   |       |       +--> SQLBindParameter
   |       +--> execute_statement()
   |               |
   |               +--> SQLExecute
   |
   +--> fetch()
   |       |
   |       +--> SQLFetch / SQLGetData
   |       v
   |    odbc_record
   |
   +--> more()
           |
           +--> SQLMoreResults
```

## Query and statement paths

`query()`/`execute()` provide formatted SQL execution. The direct path uses `SQLExecDirect`.

For parameterized statements, `prepare_statement()` creates a prepared statement, `bind_statement_parameter()` maps a caller buffer and ODBC C/SQL types to `SQLBindParameter`, and `execute_statement()` invokes `SQLExecute`.

The class supports synchronous and asynchronous query modes. In asynchronous mode, `close()` uses `SQLCancel` before freeing the statement handle.

## Result-set handling

After execution, `build_fieldinfo()` uses `SQLNumResultCols` and `SQLDescribeCol` to construct field metadata. `fetch()` obtains rows with `SQLFetch` and retrieves column data with `SQLGetData`, mapping ODBC SQL types to suitable C-side representations before populating `odbc_field` objects in an `odbc_record`.

`get_resultset()` exposes column/row counts through `SQLNumResultCols` and `SQLRowCount`; `more()` advances through additional result sets with `SQLMoreResults`.

## Related

- `odbc_connector` — creates the query and owns the connection lifecycle
- `odbc_record` — row container produced by `fetch()`
- `odbc_field` — individual column value and conversion
- `odbc_diagnose` — diagnostics for ODBC handles
