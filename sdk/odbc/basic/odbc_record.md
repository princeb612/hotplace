## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC fetched row

## 1. Role

`odbc_record` represents one fetched row as an ordered collection of `odbc_field` objects. It provides row-level access without owning query execution or column retrieval.

## 2. Data Model

```text
odbc_record
  +-- ordered vector of odbc_field references
          |
+-- [0] field for column 1
+-- [1] field for column 2
+-- [n] field for column n
```

The same container type serves two different roles inside this module: `_field_information` stores one field descriptor per result column, while a caller-owned record stores the values for one fetched row. The container itself does not distinguish those roles; the query determines the meaning of each field collection.

`count()` returns the current vector size, `get_field(index)` uses a zero-based index, and name-based lookup resolves a field through its metadata. The record retains field objects through the project's shared-reference mechanism.

## 3. Behavior Model

### Metadata population versus row population

- During execution, `odbc_query::build_fieldinfo()` describes columns and appends metadata-bearing fields to its internal `_field_information` record.
- During `fetch(record)`, the query clears the destination record, advances the native cursor with `SQLFetch`, retrieves each column with `SQLGetData`, creates value-bearing fields, and appends them in column order.
- The record therefore reflects the most recently fetched row only; it does not accumulate all rows in the result set.

```text
build_fieldinfo() -> metadata record (one field per column)

fetch(record)
  -> clear old row
  -> SQLFetch
  -> SQLGetData for each column
  -> append value fields
  -> record now represents this row
```

`clear()` releases the stored field references and empties the vector so it can be reused. `get_field(index)` is zero-based and uses bounds-checked vector access; valid indices are `0..count()-1`. `get_field(name)` is useful when column metadata is present, but callers should not assume names are unique in every SQL result.

## 5. Relationships

- [`odbc_query.md`](odbc_query.md) — populates records during row fetching
- [`odbc_field.md`](odbc_field.md) — metadata and values for individual columns
- [`../README.md`](README.md) — wrapper-class flow

## 6. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
