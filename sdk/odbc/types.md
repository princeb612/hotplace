# types

`types.hpp` is the shared ODBC type boundary between the parent SDK and the concrete `basic` implementation.

It includes the native ODBC headers and defines the hotplace ODBC error category used to translate `SQLRETURN` values into the project's common `return_t` model.

## Error mapping

```text
SQL_SUCCESS / SQL_SUCCESS_WITH_INFO
              |
              v
      errorcode_t::success

SQL_INVALID_HANDLE
              |
              v
      errorcode_t::invalid_context

other SQL errors
              |
              v
      errorcode_t::internal_error
```

`sql_query_mode_t` distinguishes synchronous and asynchronous query handling. Forward declarations for the ODBC implementation classes keep the public type boundary lightweight.
