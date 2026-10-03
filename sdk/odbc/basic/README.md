## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

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

#### Source / test relationship

The implementation documents map one-to-one to the principal classes, while the ODBC testcase exercises them as a single path:

```text
test/testcase/odbc
       │
       ▼
odbc_connector
       │
       ▼
odbc_query
       │
       ▼
odbc_record → odbc_field
       │
       └── errors → odbc_diagnose
```

This is intentionally a source-tree implementation map, not a database usage tutorial.

#### Module records

- [odbc_connector.md](odbc_connector.md)
- [odbc_query.md](odbc_query.md)
- [odbc_record.md](odbc_record.md)
- [odbc_field.md](odbc_field.md)
- [odbc_diagnose.md](odbc_diagnose.md)
- [odbc_sinker.md](odbc_sinker.md)
