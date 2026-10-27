## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1116                    │
│ Source basis: Revision 1116                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Shared base types

## 1. Role

`types.hpp` is the common type and platform-header foundation for `sdk/base`. It imports OS-specific definitions, declares shared byte/value aliases, and defines common enums and helpers used by the rest of the SDK.

It also defines the `HOTPLACE_*_API` declaration macros used to control symbol visibility in shared builds. Under `SUPPORT_SHARED`, Windows-family builds select `__declspec(dllexport)` for the SDK module being built and `__declspec(dllimport)` for consumers; GCC/Linux builds use default symbol visibility. The per-module macros separate the base, I/O, crypto, network, and ODBC library boundaries.

## 2. Data Model

- `byte_t` is the unsigned byte type; `binary_t` derives from `std::vector<byte_t>` and inherits its constructors and assignment operators.
- `loglevel_t` provides ordered logging levels.
- `encoding_t` identifies encoding families such as Base16, RFC-style Base16, Base64, Base64URL, and HTTP/2 Huffman.
- The header also centralizes common integer, container, and platform-related definitions used by other base headers.

- `HOTPLACE_EXPORT_API` and `HOTPLACE_IMPORT_API` represent the platform export/import mechanism on Windows-family builds. `HOTPLACE_BASE_API`, `HOTPLACE_IO_API`, `HOTPLACE_CRYPTO_API`, `HOTPLACE_NET_API`, and `HOTPLACE_ODBC_API` apply that mechanism at each SDK library boundary. For GCC/Linux shared builds, these module macros use `__attribute__((visibility("default")))` when supported; when shared support is not enabled, they expand to an empty declaration marker.

The Linux and Windows branches include their corresponding platform type headers and OS/network headers. Consequently, including this file can bring platform declarations into a translation unit; it is not a minimal, platform-neutral type-only header.

## 3. Behavior Model

`loglevel_helper` converts numeric or textual values to levels and levels back to uppercase names. The string path normalizes input and handles recognized aliases; unknown values use the documented default/`UNKNOWN` behavior.

**Binary representation**

`binary_t` provides vector-like byte storage. Its equality operator compares size and then byte content. It does not define the byte order or wire encoding of the stored values; those are chosen by the conversion/encoding API.

**Log-level conversion**

`loglevel_helper::to_loglevel(int)` maps recognized numeric values and falls back to the default level for unknown numbers. The string overload lowercases the input, treats `warning` as `warn`, and falls back to the default for unrecognized strings. `to_string()` returns the uppercase label or `UNKNOWN`.

**Encoding identifiers**

`encoding_t` is an identifier set, not an encoder implementation. The matching encoder/decoder code defines the actual accepted syntax and error behavior.

### Shared-library declaration path

The module API macros are defined in one common header but select their behavior
from the build configuration:

```text
SUPPORT_SHARED
      │
      ├── Windows / MinGW
      │      ├── building a module  → __declspec(dllexport)
      │      └── consuming a module → __declspec(dllimport)
      │
      └── GCC / Linux
             └── default symbol visibility

HOTPLACE_BASE_API / HOTPLACE_IO_API / ...
      │
      ▼
public SDK declarations
      │
      ▼
shared-library symbols consumed by tests and applications
```

The module-specific `*_SHARED` definition identifies which SDK library is
being built. Other modules see the corresponding import declaration on
Windows-family toolchains. The macro names are API-boundary markers; they do
not by themselves configure the shared target, link dependencies, or runtime
library search path. Those responsibilities remain in the root build scripts
and CMake target definitions.

On Linux, exported declarations are only part of the shared-library boundary.
`sdk/version.script` controls the dynamic symbol set: it exports `hotplace::*`
C++ symbols and explicitly includes the Itanium ABI patterns for typeinfo
objects (`_ZTIN8hotplace*`), typeinfo names (`_ZTSN8hotplace*`), and vtables
(`_ZTVN8hotplace*`). The catch-all `local: *;` keeps other symbols hidden.
These RTTI-related patterns were added after shared-build issues on CentOS 7,
Rocky Linux 8, and Ubuntu 20; MinGW64 and MSVC did not exhibit the same issue.

The shared-build verification documented for Revision 1114 succeeded on
MinGW64, MSVC, Ubuntu 20, Rocky Linux 8, and CentOS 7. Revision 1116 also separates
the project version values into `version.txt`; the root `CMakeLists.txt`
uses them to generate consistent file-version metadata for MinGW64/MSVC
binaries. See the [Build study](../../docs/build/README.md) for the integration
path and scope.

### Concrete caller path: byte storage and log-level parsing

The shared aliases are used directly in ordinary SDK code:

```cpp
binary_t payload;
payload.push_back(0x16);
payload.push_back(0x03);
payload.push_back(0x03);

loglevel_t level = loglevel_helper::to_loglevel("debug");
```

`binary_t` is a byte vector, so its contents represent an explicit sequence of octets rather than a C string. `loglevel_helper::to_loglevel()` accepts the textual configuration value and maps recognized names to the corresponding enum; an unrecognized or null name falls back to `default_loglevel`. These two utilities share the base type layer but solve independent problems.

The log-level conversion is also used when interpreting command-line or configuration options; the helper is a mapping function, not a logger configuration operation by itself.

## 4. Relationships

- `sdk/base/error.hpp` — return codes and platform error normalization.
- `sdk/base/encoding/` — consumes `binary_t` and encoding identifiers.
- `sdk/base/stream/` — byte/text stream utilities.
- `sdk/base/system/linux/types.hpp` and `sdk/base/system/windows/types.hpp` — platform-specific type definitions.

## 5. References

No external references are listed.
