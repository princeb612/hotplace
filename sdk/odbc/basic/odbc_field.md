## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC column value

## 1. Role

`odbc_field` represents one column in a fetched row. It retains the column index, data/SQL type information, column size, optional field metadata, and the retrieved value used by the public conversion methods.

## 2. Data Model

```text
odbc_field
  +-- _index         : column ordinal
  +-- _data_type     : retrieval/storage type
  +-- _column_type   : SQL column type
  +-- _column_size   : reported size
  +-- _field_info    : optional column-description reference
  +-- _field_data    : scalar union or allocated buffer
  +-- _datetime      : datetime_t for date/time representations
```

The payload is type-directed rather than a universal byte array:

- Character/XML and wide-character values use allocated, terminated buffers.
- Binary values use an allocated buffer with a length derived from the column data size.
- Bit and selected integer types use the scalar integer member; floating-point types use scalar float/double members.
- Date/time values use the internal `datetime_t` representation.
- `_field_info` can associate a value with its column description, such as the column name.

The distinction between `_data_type` and `_column_type` matters: the former selects the field's storage/conversion path, while the latter records the SQL-side type information.

## 3. Behavior Model

### Creation from query output

1. `odbc_query::fetch()` selects an ODBC C retrieval type for each SQL column.
2. `SQLGetData` fills a temporary buffer; chunked values are accumulated before field construction.
3. The query constructs `odbc_field` with the ordinal, selected data type, SQL column type, size, bytes, and available metadata.
4. The field copies buffer-backed values into its own allocation or stores scalar/date-time data in its corresponding member. The record then retains the field object.

### Conversion and lifetime

```text
SQL metadata + SQLGetData bytes
              |
              v
          odbc_field
          /    |     \\
    buffer   scalar  datetime_t
       |        |       |
 as_string() as_integer()/as_double() type-aware date/time access
```

`as_integer()` and `as_double()` return direct values for selected scalar types and otherwise use text conversion for supported representations. Binary and timestamp cases do not provide a meaningful generic numeric conversion and fall through to the method's default value. These helpers are convenience conversions, not a guarantee of lossless conversion across SQL types.

The destructor frees buffer-backed data according to `_data_type`; scalar members and `_datetime` are stored inline. Because storage and conversion are type-specific, callers should preserve the semantic SQL type when interpreting binary, large numeric, and date/time values.

## 5. Relationships

- [`odbc_record.md`](odbc_record.md) — holds fields for a fetched row
- [`odbc_query.md`](odbc_query.md) — selects retrieval types and constructs field objects
- [`../README.md`](README.md) — overall result traversal

## 6. References

- [Microsoft ODBC API Reference](https://learn.microsoft.com/en-us/sql/odbc/reference/syntax/odbc-api-reference?view=sql-server-ver17)
