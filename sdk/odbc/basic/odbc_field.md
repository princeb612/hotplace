## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC column value

## 1. Role

`odbc_field` represents one column in a fetched row. It retains the column index, data/SQL type information, column size, optional field metadata, and the retrieved value used by the public conversion methods.

## 2. Data Model

```text
column description + retrieved data
                 |
                 v
             odbc_field
                 |
       +---------+----------+
       |         |          |
  get_field_name()  as_string()  as_integer() / as_double()
```

The implementation stores scalar values in a small union and uses a pointer for string, binary, and other buffer-backed values. Timestamp values use the internal datetime representation. A field may refer to the corresponding field-information object produced while the query describes the result set.

## 3. Behavior Model

The query chooses an ODBC C type for `SQLGetData` based on the SQL column type and constructs a field from the returned bytes and the metadata. `get_field_name()` converts the stored column name to the requested string representation. `as_string()` converts or copies the value into an ANSI string and, in Unicode builds, a wide string. `as_integer()` and `as_double()` use the stored scalar value for selected numeric types and conversion helpers for other representations.

These methods are convenience conversions, not a lossless representation of every SQL type. In particular, binary and date/time values have type-specific storage paths, so callers should choose a conversion that matches the column's semantics rather than assume every value can be safely represented as an integer or double.

## 4. Relationships

- [`odbc_record.md`](odbc_record.md) — holds fields for a fetched row
- [`odbc_query.md`](odbc_query.md) — selects retrieval types and constructs field objects
- [`../README.md`](README.md) — overall result traversal

## 5. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
