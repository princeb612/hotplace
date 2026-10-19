## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# windows_registry

## 1. Role

`windows_registry.hpp` / `windows_registry.cpp` provides Windows Registry access through the SDK's system layer, with charset-specific support in `windows_registry_charset.cpp`.

```text
SDK code
   |
   v
windows_registry
   |
   v
Windows Registry API
```

This is a Windows platform utility rather than part of the generic I/O event model.

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

### Related source

- `sdk/io/system/windows_registry.hpp`
- `sdk/io/system/windows_registry.cpp`
- `sdk/io/system/windows_registry_charset.cpp`
