## Publication

```text
hotplace source tree
Edition 1 · Revision 1105
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC diagnostic callbacks

## 1. Role

Converts native ODBC diagnostic records into hotplace callback-oriented error reporting.

## 2. Model

`odbc_diagnose` converts native ODBC diagnostic records into hotplace's callback-oriented error reporting path.

## Flow

```text
ODBC operation
      |
      | failure / diagnostic information
      v
SQLGetDiagRec
      |
      v
odbc_diagnose
      |
      +--> native error
      +--> SQLSTATE
      +--> message
      |
      v
DATABASE_ERRORHANDLER callbacks
```

The class is a process-level singleton accessed through `get_instance()`. `diagnose()` walks the diagnostic records for an ODBC handle using `SQLGetDiagRec` and forwards each record to registered handlers.

A handler receives the native error code, SQLSTATE, message, a control flag and caller-supplied context. This keeps database-specific diagnostics outside the connector/query implementation while allowing an application to decide how errors should be logged or handled.

The sample testcase registers a handler that writes the native error, SQLSTATE and message through the hotplace logger.

## 3. Important behavior and lifetime

`diagnose()` walks diagnostic records using `SQLGetDiagRec` and forwards native error, SQLSTATE and message to registered handlers. The class is a singleton and protects the handler list with a critical section.

## 4. Example from the source tests

`sample.cpp` registers `dbdiag_handler`, which logs the native error code, SQLSTATE and message. Whether the callback runs depends on an ODBC operation producing diagnostics.

## 5. Relationships

- `odbc_connector` / `odbc_query` / `odbc_record` / `odbc_field` participate in the connection-to-row path; the exact relation depends on this class.

## 6. References

- `sdk/odbc/basic/odbc_diagnose.hpp`
- `test/testcase/odbc/sample.cpp`
