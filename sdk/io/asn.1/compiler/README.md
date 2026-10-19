## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Compiler

## 1. Role

Compiler-oriented ASN.1 processing in hotplace, including parsing, semantic processing, and source/output generation flow.

## 2. Model

### Documents

- [Compiler implementation record](asn1-compiler.md)
- [Compiler flow](compiler-flow.md)

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`

## 5. Relationships

### Related areas

- `../basic/` — ASN.1 notation/type model
- `../loader/` — loading and interpretation
- `../runtime/` — runtime representation
- `../../parser/` — parser implementation

## 6. References

Source references and related documents are retained below where available.
