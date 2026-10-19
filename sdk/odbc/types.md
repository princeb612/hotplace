## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC shared types

## 1. Role

`types.hpp` defines the shared ODBC type boundary between the parent SDK and the concrete `basic` implementation.

## 2. Model

It includes native ODBC headers, declares implementation classes, defines `sql_query_mode_t` for synchronous/asynchronous query handling, and maps ODBC return values to hotplace `return_t` errors.

```text
SQL_SUCCESS / SQL_SUCCESS_WITH_INFO -> errorcode_t::success
SQL_INVALID_HANDLE                  -> errorcode_t::invalid_context
other SQL errors                    -> errorcode_t::internal_error
```

## 3. Important behavior and lifetime

The mapping is intentionally coarse: it converts native SQL return status into hotplace error categories. Detailed SQLSTATE and diagnostic messages are handled through `odbc_diagnose`, rather than encoded in this type header.

## 4. Example from the source tests

`test/testcase/odbc/sample.cpp` checks whether `connect()` and `query()` return `errorcode_t::success` before proceeding. The sample does not directly unit-test every mapping branch in `types.hpp`.

## 5. Relationships

`odbc_connector` and `odbc_query` consume these shared types. `odbc_diagnose` supplies diagnostic detail when native ODBC operations fail.

## 6. References

- `types.hpp`
- `basic/odbc_connector.hpp`
- `basic/odbc_query.hpp`
- `test/testcase/odbc/sample.cpp`
