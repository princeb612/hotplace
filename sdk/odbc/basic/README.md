## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC basic implementation

## 1. Role

`basic/` contains the concrete ODBC wrappers. These classes keep the native ODBC handle, statement, row, and diagnostic concepts visible through a small hotplace-facing interface; they do not introduce a database-independent object-relational model.

## 2. Data Model

The module's data model is organized around native resource ownership, query metadata, row values, and diagnostic registration.

```text
odbc_connector
  +-- _env_handle : HENV
  +-- environment and connection-pooling configuration
          |
          v
odbc_query
  +-- _dbc_handle : HDBC
  +-- _stmt_handle : HSTMT
  +-- _sql_mode : sync_query | async_query
  +-- _field_information : odbc_record
  |       +-- odbc_field[] (column descriptors)
  +-- caller-owned odbc_record
  |       +-- odbc_field[] (one row of values)
  +-- execution/result status

odbc_diagnose
  +-- registered handlers
          +-- callback
          +-- caller context

odbc_sinker
  +-- retained odbc_query reference
  +-- timeout threshold
  +-- monotonic start timestamp
```

- **Native resource ownership:** the connector owns HENV; the query manages the associated HDBC and statement operations through HSTMT. The query lifetime governs connection and statement cleanup.
- **Column metadata:** _field_information describes the current result set's columns. It is not the row currently returned to the caller.
- **Row values:** a caller-provided odbc_record contains odbc_field values for one fetched row; it is not a complete buffered result set.
- **Diagnostics:** the singleton diagnostic service stores handler registrations (callback plus caller context). Individual diagnostic records are obtained from native ODBC handles when requested.
- **Polling state:** the sinker retains a query reference and timeout timing state; it does not own an independent connection or statement handle.

## 3. Behavior Model

### Connection and statement lifecycle

1. Constructing `odbc_connector` invokes `odbc_startup()`: configure connection pooling, allocate `HENV`, and set the environment to ODBC 3.
2. `connect()` creates a native connection (`HDBC`) for the supplied connection string and returns an `odbc_query` associated with it.
3. The query uses `HSTMT` for SQL execution. `close()` frees the statement and clears column metadata; in asynchronous mode it first requests cancellation with `SQLCancel`.
4. Releasing the query eventually runs its destructor, which closes any statement and disconnects/frees `HDBC`. Destroying the connector frees `HENV`.

### Statement-to-row flow

```text
SQL text / prepared parameters
            |
            v
  execute or prepare/bind/execute
            |
            v
  SQLNumResultCols + SQLDescribeCol
            |
            v
  _field_information (column metadata)
            |
            v
  SQLFetch
            |
            +-- SQL_NO_DATA --> errorcode_t::no_data
            |
            v
  SQLGetData per column
            |
            v
  odbc_field(value + type metadata)
            |
            v
  caller's odbc_record (one row)
```

`more()` advances with `SQLMoreResults` and rebuilds metadata on success. `get_resultset()` asks ODBC for column and row counts; a reported row count of `-1` is normalized to zero, so it should not be interpreted as an exact row count for every statement.

### Errors, diagnostics, and asynchronous execution

ODBC `SQLRETURN` conversion is deliberately coarse (`success`, `invalid_context`, or `internal_error`). When native detail is needed, `odbc_diagnose` iterates `SQLGetDiagRec` records and dispatches them to registered callbacks. For asynchronous execution, `odbc_sinker::ready()` calls `execute_statement()` again while it reports `busy`; elapsed monotonic time is compared with the configured timeout, and timeout closes the query to cancel/free the statement.

Build integration collects common `basic/*.cpp` files, adds `basic/unicode/*.cpp` on Windows, and links the platform `odbc` library. Driver-manager availability, driver behavior, SQL type mappings, and character-width configuration affect runtime results.

## 4. Relationships
- [`odbc_connector.md`](odbc_connector.md) — environment, connection, and query creation
- [`odbc_query.md`](odbc_query.md) — statement execution, metadata, fetching, and result sets
- [`odbc_record.md`](odbc_record.md) and [`odbc_field.md`](odbc_field.md) — fetched rows and their column values
- [`odbc_diagnose.md`](odbc_diagnose.md) — diagnostic record dispatch
- [`odbc_sinker.md`](odbc_sinker.md) — asynchronous readiness and timeout behavior
- [`../../odbc.hpp`](../../odbc.hpp) and [`../types.md`](../types.md) — module contract and shared types
- [`../../../test/testcase/odbc/README.md`](../../../test/testcase/odbc/README.md) — checked-in integration sample and its limits

## 5. References
- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
