## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC diagnostic callbacks

## 1. Role

`odbc_diagnose` reads native ODBC diagnostic records and forwards them to registered application callbacks. It keeps SQLSTATE, native error codes, and driver-provided messages separate from the module's coarse `return_t` conversion.

## 2. Data Model

```text
odbc_diagnose (singleton)
  +-- registered handler list
          +-- callback
          +-- opaque caller context

diagnostic record (native ODBC data)
  +-- native error code
  +-- SQLSTATE
  +-- driver message

diagnostic request context
  +-- native handle type
  +-- native handle
```

Handler registrations pair a callback with an opaque caller-supplied context pointer. A diagnostic record contains native ODBC error information and is distinct from the hotplace return_t / errorcode_t summary of an operation. The handle type and handle identify the native diagnostic source for a request; they are inputs to collection, not persistent diagnostic payload fields.

## 3. Behavior Model

### Diagnostic collection and dispatch

1. The caller supplies the native handle type and handle to `diagnose()`, typically after an operation fails.
2. The implementation advances through diagnostic record numbers using `SQLGetDiagRec`.
3. Collection stops when ODBC reports `SQL_NO_DATA` or `SQL_INVALID_HANDLE`; each available record carries its native code, SQLSTATE, and message.
4. `run_handlers()` dispatches the record to registered callbacks while holding the handler-list critical section.
5. A callback can change the control flag to stop dispatching the current record to subsequent handlers.

```text
failed native ODBC operation
          |
          v
diagnose(handle type, handle)
          |
          v
SQLGetDiagRec: record 1, 2, ... until stop status
          |
          v
run_handlers(code, state, message, control, context)
```

This is an explicitly requested diagnostic path, not automatic enrichment of every failed call. Callers should first interpret the original operation's return status, then request diagnostics when native driver detail is needed. Since callbacks execute while the handler-list critical section is held, callback behavior should account for that synchronization boundary.

## 4. Relationships
- [`odbc_connector.md`](odbc_connector.md) and [`odbc_query.md`](odbc_query.md) — native handles whose failures may have diagnostic records
- [`../README.md`](README.md) — shared ODBC wrapper model
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample registers a callback that logs diagnostic details

## 5. References
- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
