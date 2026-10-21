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

## 4. Relationships

- `sdk/base/system/error.hpp` — `error_advisor`, `error_traits`, categories and diagnostic hints.
- `sdk/base/syntax.hpp` — uses `errorcode_t` in allocation/error-handling macros.
- `sdk/base/callback.hpp` — callback signatures return `return_t`.
- `sdk/base/unittest/` — reports test outcomes using shared error/category conventions. `error.hpp/.cpp` define the shared codes and wrapper; this is the common representation that the system error-advisor layer interprets.
