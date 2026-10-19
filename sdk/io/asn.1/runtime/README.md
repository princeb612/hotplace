## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Runtime

## 1. Role

Runtime ASN.1 representation used after parsing/loading, including module definitions, the module registry, and weakly typed/strongly typed object flows.

For Revision 1104, `asn1_module` represents one ASN.1 module and `asn1_modules` is the singleton registry for named module instances. `asn1_module_context` is no longer the current name.

## 2. Model

### Documents

- [Module implementation record](asn1_module.md)
- [ASN.1 parser](asn1_parser.md)
- [ASN.1 publisher](asn1_publisher.md)
- [Runtime examples](runtime-examples.md)

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/runtime/`
- `test/testcase/asn.1/`

## 5. Relationships

### Related areas

- `../basic/` — type/tag/constraint definitions
- `../loader/` — loading flow
- `../compiler/` — compiler/source-generation direction
- `../../parser/` — syntax parsing

## 6. References

Source references and related documents are retained below where available.
