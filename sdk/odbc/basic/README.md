### ODBC connector, query and record implementation

`basic/` contains the concrete hotplace ODBC wrapper. It maps the native ODBC handle model into a small set of C++11-oriented classes while retaining direct access to ODBC concepts such as SQL statements, result sets, diagnostics and parameter binding.

```text
odbc_connector
     |
     v
odbc_query
  |       \
  |        +--> parameter binding / execution
  v
odbc_record
     |
     v
odbc_field

odbc_diagnose  <---- ODBC diagnostic records
odbc_sinker    <---- query readiness / asynchronous integration
```

The implementation has ANSI/Unicode paths. Windows-specific Unicode source files live under `unicode/`; the main build selects the platform ODBC library and those Unicode sources on Windows.

#### Module records

- [odbc_connector.md](odbc_connector.md)
- [odbc_query.md](odbc_query.md)
- [odbc_record.md](odbc_record.md)
- [odbc_field.md](odbc_field.md)
- [odbc_diagnose.md](odbc_diagnose.md)
- [odbc_sinker.md](odbc_sinker.md)
