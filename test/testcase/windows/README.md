# Windows-specific test cases

This directory contains Windows-only utility tests and their shared test harness.

## Current test source

- [`sample.cpp`](sample.cpp)
  - `test_enum_modules()` exercises process module enumeration through the hotplace helper and logs module paths.
  - `test_trace()` covers the Windows trace-related path.
- [`CMakeLists.txt`](CMakeLists.txt) defines how these sources are included in the test build.

The adjacent manifest/resource note concerns Windows application manifests and side-by-side assembly behavior; it is a platform-specific test concern, not a portable SDK contract. See the [Microsoft application manifest reference](https://learn.microsoft.com/ko-kr/windows/win32/sbscs/application-manifests).

These tests should be interpreted in a Windows build environment. Their presence does not imply that the same APIs or behaviors are available on Linux.

