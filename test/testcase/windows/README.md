## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: Windows-specific testcase inventory
```

# Windows-specific testcases

## 1. Role

This directory contains Windows-only utility tests and their shared testcase harness. The APIs and behaviors here are platform-specific and should not be interpreted as portable SDK contracts.

## 2. Test model

- `sample.cpp` — Windows-specific test entry point.
- `CMakeLists.txt` — target registration/build integration.
- `test_enum_modules()` — exercises process module enumeration through the hotplace helper and logs module paths.
- `test_trace()` — covers the Windows trace-related path.

The adjacent manifest/resource note concerns Windows application manifests and side-by-side assembly behavior.

## 3. Example: enumerate process modules

The source path invokes `test_enum_modules()`, obtains process module information through the hotplace helper, and logs module paths. This is a Windows API integration check; it does not establish that equivalent module-enumeration behavior exists on Linux.

## 4. Test and verification status

### 4.1 Source-level coverage

The current directory covers module enumeration and trace behavior. It is not an exhaustive test of Windows registry, sockets, ODBC, or all platform-specific SDK code.

### 4.2 Documentation and verification status

A runtime claim must identify a Windows build/compiler and the corresponding test report. This README does not claim execution during the documentation update.

## 5. Relationships

- `sdk/io/system/windows_registry.md` — Windows registry wrapper.
- `sdk/io/system/` — OS-specific facilities.
- `test/README.md` — environment-specific verification matrix.

## 6. References

- `sample.cpp`
- `CMakeLists.txt`
- [Microsoft application manifest reference](https://learn.microsoft.com/ko-kr/windows/win32/sbscs/application-manifests)
