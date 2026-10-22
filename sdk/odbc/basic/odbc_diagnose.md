## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC diagnostic callbacks

## 1. Role

`odbc_diagnose` reads native ODBC diagnostic records and forwards them to registered application callbacks. It keeps SQLSTATE, native error codes, and driver-provided messages separate from the module's coarse `return_t` conversion.

## 2. Data Model

```text
ODBC operation on a native handle
             |
             v
       SQLGetDiagRec
             |
             v
       odbc_diagnose
             |
             +-- native error code
             +-- SQLSTATE
             +-- message
             |
             v
       registered callbacks
```

The class is a singleton. Each handler registration stores a callback and caller-supplied context pointer. The callback receives the native error code, state, message, a control flag, and the context.

## 3. Behavior Model

`diagnose()` iterates diagnostic records using `SQLGetDiagRec` until ODBC returns `SQL_NO_DATA` or `SQL_INVALID_HANDLE`. Each record is passed to `run_handlers()`, which invokes registered callbacks while holding the handler-list critical section. A callback can set the control flag to false to stop dispatching the current diagnostic record to later handlers.

This is diagnostic reporting, not a replacement for checking the return value of the original ODBC call. The diagnostic path runs only when code asks the singleton to inspect a handle, commonly after a native operation fails.

## 4. Relationships

- [`odbc_connector.md`](odbc_connector.md) and [`odbc_query.md`](odbc_query.md) — native handles whose failures may have diagnostic records
- [`../README.md`](README.md) — shared ODBC wrapper model
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample registers a callback that logs diagnostic details

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
