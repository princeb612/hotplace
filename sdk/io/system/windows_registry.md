# windows_registry

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

## Related source

- `sdk/io/system/windows_registry.hpp`
- `sdk/io/system/windows_registry.cpp`
- `sdk/io/system/windows_registry_charset.cpp`
