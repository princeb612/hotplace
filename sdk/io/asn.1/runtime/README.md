# ASN.1 Runtime

Runtime ASN.1 representation used after parsing/loading, including module definitions, the module registry, and weakly typed/strongly typed object flows.

For Revision 1104, `asn1_module` represents one ASN.1 module and `asn1_modules` is the singleton registry for named module instances. `asn1_module_context` is no longer the current name.

## Documents

- [Module implementation record](asn1_module.md)
- [ASN.1 parser](asn1_parser.md)
- [ASN.1 publisher](asn1_publisher.md)
- [Runtime examples](runtime-examples.md)

## Related areas

- `../basic/` — type/tag/constraint definitions
- `../loader/` — loading flow
- `../compiler/` — compiler/source-generation direction
- `../../parser/` — syntax parsing

## Related tests

- `test/testcase/asn.1/runtime/`
- `test/testcase/asn.1/`
