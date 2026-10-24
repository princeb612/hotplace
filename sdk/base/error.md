## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Error codes and return values

## 1. Role

`error.hpp/.cpp` defines hotplace's cross-platform return-code representation and adapts operating-system errors into `return_t`. It is the shared error-value layer; `sdk/base/system/error.hpp` separately provides error descriptions, categories, and traits.

## 2. Data Model

- `errorcode_t` contains success, project-defined errors, and platform-specific values. On Linux, the enum includes errno and resolver error ranges; Windows uses the corresponding system error conventions.
- `return_t` wraps a numeric code and exposes helpers such as `error_code()`, `error_message()`, and `category()`.
- `get_lasterror(code, flags)` normalizes a supplied or current platform error into the shared return representation.
- `ERROR_CODE_BEGIN` and `WARN_CODE_BEGIN` mark reserved ranges for project-defined error and warning codes.

The enum values are part of the source-level compatibility contract. Do not renumber existing values casually: callers and diagnostics may depend on their numeric representation.

## 3. Behavior Model

**`return_t::error_code()`**

Delegates symbolic code formatting to `error_advisor` from `system/error.hpp`.

**`return_t::error_message()`**

For project-defined codes, asks `error_advisor` for the message. For platform codes, uses the native message mechanism: `FormatMessageA` on Windows and `strerror_r` on Linux. It trims trailing CR/LF on the Windows path and falls back to an unknown-error string when message retrieval fails.

**`return_t::category()`**

Delegates category classification to `error_advisor`; the category is not inferred solely from the numeric value in this method.

**`get_lasterror(code, flags)`**

On Linux, positive values are treated as errno values. Negative values are disambiguated between resolver errors and negative kernel errno conventions, with `EAI_SYSTEM` using the current `errno`. On Windows, a zero flag selects `GetLastError()`; the Winsock flag selects `WSAGetLastError()`. The input parameter is therefore interpreted differently by platform and flag.

### Concrete caller path: normalize a platform resolver error

Socket creation uses `get_lasterror()` when the platform's address-resolution call fails:

```cpp
ret_function = getaddrinfo(address_pointer, string_port, &hints, &addrinf);
if (0 != ret_function) {
    ret = get_lasterror(ret_function, wsaerror);
    __leave2;
}
```

This is the practical reason for a shared return representation: the socket layer returns one `return_t` shape even though the native resolver error conventions differ by platform. The helper interprets the supplied result and flag; it does not merely read the current `errno` in every case. The caller then propagates `ret` through its own failure path.

Source: `sdk/io/system/socket.cpp`, `create_socket()`.

## 4. Relationships

- `sdk/base/system/error.hpp` — `error_advisor`, `error_traits`, categories and diagnostic hints.
- `sdk/base/syntax.hpp` — uses `errorcode_t` in allocation/error-handling macros.
- `sdk/base/callback.hpp` — callback signatures return `return_t`.
- `sdk/base/unittest/` — reports test outcomes using shared error/category conventions. `error.hpp/.cpp` define the shared codes and wrapper; this is the common representation that the system error-advisor layer interprets.

## 5. References

No external references are listed.
