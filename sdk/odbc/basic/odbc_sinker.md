## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC query readiness adapter

## 1. Role

Bridges an `odbc_query` into the surrounding sink/readiness infrastructure; it is not a separate database abstraction.

## 2. Model

`odbc_sinker` is a small integration object around an `odbc_query` and timeout value. It provides a readiness check used by code that treats a query as a sink/source participant rather than interacting with the query object directly.

The implementation is intentionally small compared with `odbc_connector` and `odbc_query`; it does not introduce another database abstraction. Its role is to bridge an ODBC query into the surrounding hotplace asynchronous/sink-oriented infrastructure.

## Relationship

```text
odbc_connector
      |
      v
odbc_query
      |
      v
odbc_sinker
      |
      +--> ready()
```

The sink retains the query reference and releases it when destroyed.

## 3. Important behavior and lifetime

The object retains the query reference. `ready()` returns success immediately for synchronous mode. For asynchronous mode it checks execution readiness and returns timeout after the configured duration, calling `close()` to cancel when the timeout expires. Destruction releases the query reference.

## 4. Example from the source tests

The checked-in ODBC sample does not instantiate `odbc_sinker`; its behavior is documented from `odbc_sinker.cpp`, not claimed as covered by that sample.

## 5. Relationships

- `odbc_connector` / `odbc_query` / `odbc_record` / `odbc_field` participate in the connection-to-row path; the exact relation depends on this class.

## 6. References

- `sdk/odbc/basic/odbc_sinker.hpp`
- `test/testcase/odbc/sample.cpp`
