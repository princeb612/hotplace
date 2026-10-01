# winpe

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

## Related source

- `sdk/io/system/winpe.hpp`
- `sdk/io/system/winpe.cpp`
- `sdk/io/system/winnt.hpp`

## Related area

- `sdk/crypto/authenticode/` — Authenticode verification built on PE/certificate structures
