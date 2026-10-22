## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC connection lifecycle

## 1. Role

`odbc_connector` initializes the ODBC environment and creates a query associated with a database connection. It provides connection-status, disconnect, and query-close operations around native ODBC handles.

## 2. Data Model

```text
odbc_connector
   |
   +-- HENV  environment handle
   |
   +-- connect(connection string)
          |
          +-- HDBC connection handle
                 |
                 +-- odbc_query
                        +-- HSTMT statement handle
```

The connector stores the environment handle (`HENV`). The returned `odbc_query` is associated with the connection handle (`HDBC`) and manages the statement handle. The query destructor closes the statement and disconnects/frees its connection handle, so callers should release the query through its lifetime mechanism rather than assume the connection is independent.

## 3. Behavior Model

Construction calls `odbc_startup()`, which requests connection pooling, allocates an environment handle, and selects ODBC 3. The startup path reports failure if the relevant ODBC setup calls fail and attempts to free an allocated environment handle during cleanup. The destructor calls `odbc_cleanup()` to free the environment.

- `connect()` accepts an ANSI connection string and provides a wide-string overload in Unicode builds; it returns the created query through an output parameter.
- `disconnect()` calls `SQLDisconnect` and frees the native connection handle.
- `is_connected()` checks `SQL_ATTR_CONNECTION_DEAD`.
- `close()` releases the query reference; it does not itself implement a second native connection lifecycle.
- `is_connection_pooled()` reads the process/driver-manager pooling setting.

The class uses hotplace's shared-reference mechanism for its own lifetime management, while database resources remain native ODBC handles. Success depends on the installed ODBC driver manager and the supplied connection string.

## 4. Relationships

- [`../README.md`](../README.md) — module data flow
- [`odbc_query.md`](odbc_query.md) — statement and connection-associated query lifetime
- [`odbc_diagnose.md`](odbc_diagnose.md) — environment and statement diagnostics
- [`../../types.md`](../../types.md) — shared return-code conversion and query modes
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample's caller-supplied connection configuration

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
