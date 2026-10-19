## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# winpe

## 1. Role

`winpe.hpp` / `winpe.cpp` contains Windows Portable Executable (PE) related structures and parsing support used by the system layer.

```text
PE image
   |
   v
winpe
   |
   +---- headers / sections
   +---- Windows-specific layout
```

This is a platform-format utility. It should be distinguished from `sdk/crypto/authenticode/`, which uses PE information as part of Authenticode verification.

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

### Related area

- `sdk/crypto/authenticode/` — Authenticode verification built on PE/certificate structures

## 6. References

### Related source

- `sdk/io/system/winpe.hpp`
- `sdk/io/system/winpe.cpp`
- `sdk/io/system/winnt.hpp`
