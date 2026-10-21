## Publication

```text
hotplace source tree
Edition 1 · Revision 1105
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC column value

## 1. Role

Represents one column of an ODBC result row, retaining column metadata and retrieved data in forms convertible to common hotplace types.

## 2. Model

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

## 3. Important behavior and lifetime

The conversion helpers include string, integer and floating-point access. The query/result path chooses ODBC C types for `SQLGetData` and constructs fields from column metadata and retrieved values.

## 4. Example from the source tests

`sample.cpp` calls `get_field_name()` and `as_string()` on each returned field. It does not exercise all conversion helpers.

## 5. Relationships

- `odbc_record` — owns fields for one row
- `odbc_query` — retrieves and constructs fields from the ODBC result set

## 6. References

- `sdk/odbc/basic/odbc_field.hpp`
- `test/testcase/odbc/sample.cpp`
