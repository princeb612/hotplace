## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ODBC basic implementation

## 1. Role

`basic/` contains the concrete ODBC wrapper classes. It maps native ODBC handles and operations to hotplace-oriented connector, query, record, field, diagnostics, and readiness objects.

## 2. Model

```text
odbc_connector -> odbc_query -> odbc_record -> odbc_field
                       |
                       +--> odbc_diagnose reports errors
odbc_sinker wraps query readiness / timeout handling
```

## 3. Important behavior and lifetime

The classes retain native ODBC behavior rather than hiding it behind a database-specific ORM. The source tree includes ANSI implementation files and Windows Unicode-specific files under `unicode/`. Build selection and native ODBC library linkage are defined in `sdk/odbc/CMakeLists.txt`.

## 4. Example from the source tests

`test/testcase/odbc/sample.cpp` demonstrates the connector → query → record → field path using a caller-supplied connection string and table name.

## 5. Relationships

- [`odbc_connector.md`](odbc_connector.md) — connection and environment lifecycle
- [`odbc_query.md`](odbc_query.md) — statements, binding and result traversal
- [`odbc_record.md`](odbc_record.md) and [`odbc_field.md`](odbc_field.md) — row and column values
- [`odbc_diagnose.md`](odbc_diagnose.md) — diagnostics
- [`odbc_sinker.md`](odbc_sinker.md) — readiness and timeout integration

## 6. References

- `sdk/odbc/basic/`
- `sdk/odbc/CMakeLists.txt`
- `test/testcase/odbc/sample.cpp`
