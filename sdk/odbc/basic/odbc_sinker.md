## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC query readiness adapter

## 1. Role

`odbc_sinker` adapts an existing `odbc_query` to the readiness/timeout interface used by surrounding asynchronous code. It does not create a connection or statement and does not provide a separate database abstraction.

## 2. Data Model

```text
odbc_sinker
  +-- retained odbc_query reference
  +-- timeout threshold : _tmo_seconds
  +-- monotonic start timestamp : _timestamp

odbc_query
  +-- execution mode : sync_query | async_query
  +-- native statement / execution state
```

The sinker retains a reference to an existing query and stores the timeout threshold and a monotonic start timestamp used for elapsed-time checks. It does not own an independent HDBC or HSTMT; those native resources remain governed by the query lifecycle. Readiness, busy status, and timeout are outcomes of the polling behavior described in the Behavior Model, not additional persistent data containers.

## 3. Behavior Model

### Readiness polling

1. Construction rejects a null query and records the current monotonic timestamp.
2. `ready()` inspects the query's `sql_query_mode_t`.
3. In `sync_query` mode, it immediately returns success; it does not execute the statement itself in this branch.
4. In `async_query` mode, it calls `execute_statement()`. A non-busy result is returned directly.
5. If execution remains busy, the sinker calculates elapsed monotonic time. When elapsed seconds are greater than the configured timeout, it returns `errorcode_t::timeout` and calls `close()` on the query.
6. Destruction releases the retained query reference.

```text
ready()
  |
+-- synchronous? -- yes --> success
  |
  no
  v
execute_statement()
  |
+-- complete/error --> propagate result
  |
+-- busy --> compare monotonic elapsed time
                 |
+-- within timeout --> busy
+-- exceeded --> timeout + query close/cancel
```

The timeout condition is strictly greater than the configured seconds, not greater-than-or-equal. This is polling around the driver's async execution mode; it does not create a scheduler or convert a synchronous driver call into asynchronous work.

## 4. Relationships
- [`odbc_query.md`](odbc_query.md) — owns statement execution and exposes the query mode
- [`../README.md`](README.md) — class-level model
- [`../../../test/testcase/odbc/testcase_odbc.md`](../../../test/testcase/odbc/testcase_odbc.md) — sample coverage boundary

## 5. References
- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
