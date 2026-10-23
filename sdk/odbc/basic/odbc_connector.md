## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC connection lifecycle

## 1. Role

`odbc_connector` initializes the ODBC environment and creates a query associated with a database connection. It provides connection-status, disconnect, and query-close operations around native ODBC handles.

## 2. Data Model

```text
odbc_connector
  +-- _env_handle : HENV
  +-- environment configuration
        +-- connection-pooling attribute
        +-- ODBC version attribute

odbc_query
  +-- _dbc_handle : HDBC
  +-- _stmt_handle : HSTMT
  +-- _sql_mode : sync_query | async_query
```

odbc_connector owns the environment handle (HENV). A query is associated with a connection handle (HDBC) and manages statement operations through HSTMT; the query lifetime is the boundary for releasing those native resources. The connector's environment lifetime is separate from an individual query's lifetime.

The connection string is passed to the native driver manager rather than represented as a parsed hotplace data structure. Connection-pooling and ODBC-version settings are environment attributes, not fields in the connection string model.

## 3. Behavior Model

### Startup and teardown

1. Construction calls `odbc_startup()`.
2. Startup requests connection pooling with `SQL_ATTR_CONNECTION_POOLING`, allocates `HENV`, then sets `SQL_ATTR_ODBC_VERSION` to ODBC 3.
3. If environment setup fails, the cleanup path diagnoses and frees an allocated environment handle and returns the native failure code.
4. Destruction calls `odbc_cleanup()`, which frees `HENV` if it exists.

### Connecting and releasing

1. `connect()` uses the configured environment and supplied connection string to create a native `HDBC`, then creates an `odbc_query` associated with that handle.
2. `is_connected()` reads `SQL_ATTR_CONNECTION_DEAD`; it reports connected only when the driver manager successfully reports `SQL_CD_FALSE`.
3. `disconnect()` requests `SQLDisconnect` and frees `HDBC`.
4. `close(query)` validates the pointer and releases the query's shared reference. Native statement/connection teardown follows the query's lifetime, rather than being an independent second lifecycle in `close()`.

```text
connector construction -> HENV setup
                             |
connect(string) -> HDBC -> odbc_query/HSTMT
                             |
query release -> HSTMT close -> HDBC disconnect/free
                             |
connector destruction -> HENV free
```

Connection success and status depend on the installed driver manager, driver, and connection string. Native diagnostic detail is available through `odbc_diagnose`; the boolean/status helpers do not themselves expose a complete diagnostic record.

## 4. Relationships
- [`README.md`](README.md) — module data flow
- [`odbc_query.md`](odbc_query.md) — statement and connection-associated query lifetime
- [`odbc_diagnose.md`](odbc_diagnose.md) — environment and statement diagnostics
- [`../../types.md`](../../types.md) — shared return-code conversion and query modes
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample's caller-supplied connection configuration

## 5. References
- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
