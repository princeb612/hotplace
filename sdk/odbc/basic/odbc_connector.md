## Publication

```text
hotplace source tree
Edition 1 · Revision 1105
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC connection lifecycle

## 1. Role

Creates and closes ODBC connections. It owns the ODBC environment handle (`HENV`) and creates an `odbc_query` associated with the connection handle (`HDBC`).

## 2. Model

`odbc_connector` is the entry point for creating and closing an ODBC database connection. It owns the ODBC environment handle (`HENV`) and creates an `odbc_query` associated with the connection handle (`HDBC`).

## Role

```text
connection string
       |
       v
odbc_connector::connect()
       |
       +--> HENV
       |
       +--> HDBC
       |
       v
odbc_query
```

The constructor initializes the ODBC environment through `odbc_startup()`. Startup enables connection pooling and selects ODBC 3 before allocating the environment handle. Cleanup releases the environment handle when the connector is destroyed.

## Connection lifecycle

- `connect()` accepts an ANSI connection string and, under Unicode builds, a wide-character connection string.
- The connector creates the database connection and returns an `odbc_query` through the output parameter.
- `disconnect()` releases the connection handle.
- `is_connected()` checks `SQL_ATTR_CONNECTION_DEAD`.
- `close()` closes the associated query.
- `is_connection_pooled()` reports the native ODBC pooling setting.

The class uses hotplace's shared-reference mechanism for its own lifetime management, but the actual database resource remains an ODBC `HDBC` handle.

## 3. Important behavior and lifetime

The source initializes pooling and ODBC 3 during startup. `connect()` accepts ANSI strings and wide strings in Unicode builds; `disconnect()` releases a connection handle; `is_connected()` checks `SQL_ATTR_CONNECTION_DEAD`; `close()` closes the associated query.

## 4. Example from the source tests

test/testcase/odbc/sample.cpp calls `connect(&rs, option.connstr.c_str())` and proceeds only when it returns success. It does not include a fixed connection string or database fixture.

## 5. Relationships

- `odbc_query` — statement and result-set operations
- `odbc_diagnose` — ODBC error diagnostics
- `sdk/odbc/types.hpp` — ODBC error conversion and query-mode types

## 6. References

- `sdk/odbc/basic/odbc_connector.hpp`
- `test/testcase/odbc/sample.cpp`
