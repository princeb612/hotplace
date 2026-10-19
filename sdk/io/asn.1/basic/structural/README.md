## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Structural Representation

## 1. Role

Structural nodes represent parsed/decoded ASN.1 structure independently from the semantic type model.

## 2. Model

### Documents

- [Structural representation study](structural.md)
- `../asn1-node.md` — implementation-level structural node record

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`

## 5. Relationships

### Related areas

- `../` — ASN.1 basic type and semantic model
- `../../../parser/` — parser/parse-tree processing
- `../../../runtime/` — runtime ASN.1 representation

## 6. References

Source references and related documents are retained below where available.
