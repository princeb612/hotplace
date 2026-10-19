## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Loader

## 1. Role

The ASN.1 loader connects parsed ASN.1 descriptions with the project's type/runtime representation.

## 2. Model

### Documents

- [Loader implementation record](asn1_loader.md)
- [Loader flow](loader-flow.md)

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`

## 5. Relationships

### Related areas

- `../basic/` — ASN.1 types and constraints
- `../runtime/` — runtime schema/type/object representation
- `../../parser/` — parsing

## 6. References

Source references and related documents are retained below where available.
