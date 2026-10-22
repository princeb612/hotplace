## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC shared types

## 1. Role

`types.hpp` defines the common ODBC type boundary used by the module's concrete wrappers. It includes native ODBC declarations and connects native status values to hotplace error handling.

## 2. Data Model

- `odbc_category` identifies the error-trait category for ODBC `SQLRETURN`.
- `error_traits<SQLRETURN, odbc_category>` converts native ODBC status into hotplace `return_t`.
- `sql_query_mode_t` distinguishes `sync_query` and `async_query`.
- Forward declarations expose the connector, diagnostic, field, query, and record types without defining their implementation here.

The conversion is intentionally coarse:

```text
SQL_SUCCESS / SQL_SUCCESS_WITH_INFO -> errorcode_t::success
SQL_INVALID_HANDLE                  -> errorcode_t::invalid_context
other SQL return values             -> errorcode_t::internal_error
```

## 3. Behavior Model

The trait treats `SQL_SUCCESS_WITH_INFO` as success, consistent with ODBC calls that complete while returning additional information. It maps an invalid native handle to `invalid_context` and other unsuccessful statuses to `internal_error`. This conversion does not preserve diagnostic details; `odbc_diagnose` retrieves those separately through ODBC diagnostic APIs.

The header also includes ODBC headers and defines compatibility macros only when the platform headers have not already provided them. `SQL_TCHAR` selection follows the build's MBCS/Unicode configuration.

## 4. Relationships

- [`README.md`](README.md) — module-level data and control flow
- [`basic/odbc_connector.md`](basic/odbc_connector.md) and [`basic/odbc_query.md`](basic/odbc_query.md) — consumers of the shared types and query mode
- [`basic/odbc_diagnose.md`](basic/odbc_diagnose.md) — detailed native diagnostic reporting
- [`test/testcase/odbc/testcase_odbc.md`](../../test/testcase/odbc/testcase_odbc.md) — integration sample and its coverage boundaries

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
