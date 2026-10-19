## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Built-in Types

## 1. Role

`basic/semantic/builtin` contains concrete implementations for selected ASN.1 built-in primitive types.

The directory currently contains focused implementations such as INTEGER and BIT STRING. They are part of the larger semantic model in `../` rather than a separate encoding/runtime subsystem.

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

### Related areas

- `../` — ASN.1 semantic type hierarchy
- `../constraints/` — constraints applied to semantic types
- `../../` — structural and visitor layers
- `../../../runtime/` — runtime ASN.1 representation

Detailed module records can be added here as the built-in type implementations grow.

## 6. References

Source references and related documents are retained below where available.
