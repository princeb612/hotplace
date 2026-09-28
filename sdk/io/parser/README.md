# Parser

The hotplace parser subsystem provides grammar parsing and parsing-table based execution used by higher-level parsers such as ASN.1.

## Documents

- [Parser design and implementation notes](parser.md) — continuous design/development record
- [LALR vs GLR](lalr-vs-glr.md) — parser approach comparison
- [Parsing table binary format](parsing-table-binary-format.md) — generated/parser table storage format

## Related areas

- `../asn.1/` — major consumer of the parser infrastructure
- `sdk/base/` — common containers, strings, streams, and utilities used by parser code

## Related tests

- `test/testcase/io/parser/`
- `test/testcase/asn.1/`

`parser.md` is intentionally retained as a long-form development/study record rather than being rewritten into a short reference document.
