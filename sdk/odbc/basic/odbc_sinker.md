## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC query readiness adapter

## 1. Role

`odbc_sinker` adapts an existing `odbc_query` to the readiness/timeout interface used by surrounding asynchronous code. It does not create a connection or statement and does not provide a separate database abstraction.

## 2. Data Model

```text
odbc_query (async_query)
       |
       v
  odbc_sinker
       |
       +-- ready()
       +-- configured timeout
       +-- retained query reference
```

The class is declared in `odbc_query.hpp`, stores a query pointer and timeout in seconds, and records a monotonic timestamp when constructed. It expects a non-null query; construction throws if none is supplied.

## 3. Behavior Model

For synchronous query mode, `ready()` returns success immediately. For asynchronous mode it calls `execute_statement()`. If execution remains busy, the sinker checks elapsed monotonic time; when the elapsed seconds exceed the configured timeout, it returns `errorcode_t::timeout` and closes the query to cancel the statement. Other execution results are passed through.

The destructor releases the retained query reference. The checked-in ODBC sample does not instantiate this adapter, so its behavior is described from the implementation rather than claimed as covered by the sample.

## 4. Relationships

- [`odbc_query.md`](odbc_query.md) — owns statement execution and exposes the query mode
- [`../README.md`](README.md) — class-level model
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample coverage boundary

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
