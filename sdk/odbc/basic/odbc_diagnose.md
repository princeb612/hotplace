# odbc_diagnose

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
