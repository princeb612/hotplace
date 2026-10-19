## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC fetched row

## 1. Role

Represents one fetched database row as a collection of `odbc_field` objects.

## 2. Model

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

## 3. Important behavior and lifetime

The record provides `count()`, index/name-based `get_field()`, append behavior through `operator<<`, and `clear()` for reuse across rows. `odbc_query::fetch()` populates it.

## 4. Example from the source tests

`sample.cpp` iterates over `record.count()` and retrieves each field by zero-based index. It prints the field name and string conversion.

## 5. Relationships

- `odbc_query` — creates/populates records
- `odbc_field` — column metadata and value conversion

## 6. References

- `sdk/odbc/basic/odbc_record.hpp`
- `test/testcase/odbc/sample.cpp`
