# odbc_field

`odbc_field` represents one column of an ODBC result row. It retains column metadata and the retrieved value in a form that can be converted to common hotplace types.

## Role

```text
ODBC column
   |
   +--> name / SQL type / size
   |
   +--> retrieved data
          |
          +--> as_string()
          +--> as_integer()
          +--> as_double()
```

The field is constructed by the query/result processing path with the column index, data/column type information, column size and retrieved data. A field may also refer to the corresponding field-information object created while describing the result set.

## Conversion

The implementation exposes conversion helpers for string, integer and floating-point use. The conversion layer hides the ODBC C-type selection performed during `SQLGetData` while keeping the result accessible through a small hotplace API.

## Related

- `odbc_record` — owns fields for one row
- `odbc_query` — retrieves and constructs fields from the ODBC result set
