## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC basic implementation

## 1. Role

`basic/` contains the concrete ODBC wrappers. These classes keep the native ODBC handle, statement, row, and diagnostic concepts visible through a small hotplace-facing interface; they do not introduce a database-independent object-relational model.

## 2. Data Model

```text
odbc_connector -> odbc_query -> odbc_record -> odbc_field
                         |                |
                         |                +-- row owns its fields
                         |
                         +-- odbc_diagnose reports native diagnostics

odbc_sinker -> retains an odbc_query reference
            -> checks async readiness and timeout
```

`odbc_sinker` is declared alongside `odbc_query` in `odbc_query.hpp`; it is a readiness adapter around an existing query, not a separate connection or statement owner.

## 3. Behavior Model

The connector initializes the ODBC environment and creates query objects. A query wraps a statement handle, supports direct and prepared execution, builds result metadata, and fills records as rows are fetched. Each record retains field objects for one row. The diagnostic singleton walks ODBC diagnostic records and invokes registered handlers. In async mode, the sinker polls query execution and closes the query when its configured timeout expires.

The module build selects the common implementation and, on Windows, any Unicode-specific sources matched by `sdk/odbc/CMakeLists.txt`; it links the platform ODBC library. Text conversion and ODBC type-width behavior therefore depend in part on the platform headers and driver manager.

## 4. Relationships

- [`odbc_connector.md`](odbc_connector.md) — environment, connection, and query creation
- [`odbc_query.md`](odbc_query.md) — statement execution, metadata, fetching, and result sets
- [`odbc_record.md`](odbc_record.md) and [`odbc_field.md`](odbc_field.md) — fetched rows and their column values
- [`odbc_diagnose.md`](odbc_diagnose.md) — diagnostic record dispatch
- [`odbc_sinker.md`](odbc_sinker.md) — asynchronous readiness and timeout behavior
- [`../README.md`](../README.md) and [`../types.md`](../types.md) — module contract and shared types
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — checked-in integration sample and its limits

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
