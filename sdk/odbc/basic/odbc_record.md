## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC fetched row

## 1. Role

`odbc_record` represents one fetched row as an ordered collection of `odbc_field` objects. It provides row-level access without owning query execution or column retrieval.

## 2. Data Model

```text
odbc_query::fetch(record)
          |
          v
     odbc_record
       |
       +-- field[0]
       +-- field[1]
       +-- field[2]
       +-- ...
```

The record stores field pointers in a vector. `count()` returns the number of fields, `get_field(index)` retrieves a field by zero-based index, and the name-based overloads retrieve fields by column name. `operator<<` appends a field.

## 3. Behavior Model

Before fetching a new row, `odbc_query::fetch()` clears the destination record. As column values are retrieved, field objects are appended to the record. `clear()` releases the field references and empties the vector so the record can be reused for another row. The record is therefore a row container, not a persistent result-set collection.

Index access uses the vector's `at()` operation, so callers should use an index within `0..count()-1`. The record's field objects expose metadata and value conversion through `odbc_field`.

## 4. Relationships

- [`odbc_query.md`](odbc_query.md) — populates records during row fetching
- [`odbc_field.md`](odbc_field.md) — metadata and values for individual columns
- [`../README.md`](README.md) — wrapper-class flow

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
