# odbc_sinker

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
