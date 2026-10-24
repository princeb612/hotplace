## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC shared types

## 1. Role

`types.hpp` defines the common ODBC type boundary used by the module's concrete wrappers. It includes native ODBC declarations and connects native status values to hotplace error handling.

## 2. Data Model

```text
ODBC native types
  +-- SQLRETURN
  +-- native handle types
  +-- SQL type constants

hotplace ODBC wrapper types
  +-- odbc_category
  +-- error_traits<SQLRETURN, odbc_category>
  +-- sql_query_mode_t
        +-- sync_query
        +-- async_query
```

odbc_category identifies the native return type for the shared error-trait system. error_traits<SQLRETURN, odbc_category> defines the adapter between native ODBC status and hotplace status. sql_query_mode_t is the execution-mode selector consumed by odbc_query and odbc_sinker; it does not represent a transaction or guarantee that a driver supports asynchronous execution.

ODBC headers provide native handles, SQL type constants, and return codes. Compatibility definitions and SQL_TCHAR selection accommodate differences in platform headers and MBCS/Unicode builds.

## 3. Behavior Model

### Return-code translation

```text
SQL_SUCCESS / SQL_SUCCESS_WITH_INFO -> errorcode_t::success
SQL_INVALID_HANDLE                  -> errorcode_t::invalid_context
other SQLRETURN values              -> errorcode_t::internal_error
```

This translation intentionally compresses native status into a small hotplace status. It does not preserve SQLSTATE, native error details, or every warning distinction; those details must be retrieved from the native handle through `odbc_diagnose` when needed.

### Query-mode effect

`sync_query` follows the normal execution path and is treated as immediately ready by `odbc_sinker`. `async_query` allows `execute_statement()` to report `busy`, which the sinker polls until completion or timeout. The mode selects behavior in the wrapper; actual support and timing remain dependent on the ODBC driver and statement operation.

## 4. Relationships
- [`basic/README.md`](basic/README.md) — module-level data and control flow
- [`basic/odbc_connector.md`](basic/odbc_connector.md) and [`basic/odbc_query.md`](basic/odbc_query.md) — consumers of the shared types and query mode
- [`basic/odbc_diagnose.md`](basic/odbc_diagnose.md) — detailed native diagnostic reporting
- [`test/testcase/odbc/README.md`](../../test/testcase/odbc/README.md) — integration sample and its coverage boundaries

## 5. References
- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
