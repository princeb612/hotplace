# odbc_record

`odbc_record` represents one fetched database row as a collection of `odbc_field` objects.

```text
SQLFetch / SQLGetData
          |
          v
    odbc_record
      /  |  \
     v   v   v
 field field field ...
```

## Role

The record owns a vector of field pointers. `operator<<` appends a field, `count()` returns the number of columns, and `get_field()` retrieves a field either by zero-based index or by column name.

`clear()` removes the fields associated with the current record so the object can be reused for another fetched row.

## Relationship to query

`odbc_query::fetch()` fills an `odbc_record`. The query determines the ODBC column metadata and retrieves the column data; the record provides the row-oriented interface used by callers.

## Related

- `odbc_query` — creates/populates records
- `odbc_field` — column metadata and value conversion
