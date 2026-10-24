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

# Character-set compatibility

## 1. Role

`charset.hpp` centralizes a small set of Windows-style text and string macros so shared code can compile across Linux and Windows. It is a compatibility shim, not a Unicode conversion library.

## 2. Data Model

On Linux, the header defines `TCHAR`, `LPTSTR`, and `LPCTSTR` as narrow-character types and maps common `_t*` names to C/POSIX functions. It also maps `stricmp` and `strnicmp` to `strcasecmp` and `strncasecmp`.

On Windows, it includes the platform `<tchar.h>` definitions instead of recreating them.

If neither MBCS nor Unicode is specified, the header defaults to `_MBCS`. On Linux, explicitly requesting Unicode triggers a compile-time error because this compatibility layer does not support that mode.

## 3. Behavior Model

**Text-mode selection**

The macros depend on compile definitions supplied before or during compilation. A caller must not assume `TCHAR` means wide text on Linux: it is always `char` here.

**Function aliases**

The `_tcs*`, `_sntprintf`, and related aliases provide source-level compatibility only. They do not guarantee identical semantics across CRTs, especially for truncation, locale-sensitive case conversion, or error reporting.

**Build constraints**

Because the Linux branch rejects Unicode mode, code that requires UTF-16/UTF-32 text must use an explicit encoding API rather than relying on `TCHAR` abstractions.

### Practical caller example: use the configured text mode deliberately

The aliases in this header are compile-time compatibility names, not runtime encoding detection. A caller using `_tcslen` or `_sntprintf` gets the mapping selected by the build definitions; it does not automatically convert UTF-8, UTF-16, or the system locale.

```text
build definitions
  -> charset.hpp selects TCHAR and _tcs* aliases
  -> caller compiles against that text type
  -> explicit encoding API is still required at a wire/file boundary
```

Use this layer for source compatibility where the supported platform mapping is sufficient. If a protocol or file format specifies UTF-8/UTF-16, make that encoding conversion explicit instead of relying on `TCHAR`.

## 4. Relationships

- `sdk/base/types.hpp` — platform-specific type and system-header setup.
- `sdk/base/callback.hpp` — uses the active MBCS/Unicode macros to select callback aliases.
- `sdk/base/inline.hpp` — shared helpers built on the compatibility definitions.
- `sdk/base/string/` — string operations and Unicode-specific implementations.

## 5. References

- [Linux man-pages: strcasecmp(3)](https://man7.org/linux/man-pages/man3/strcasecmp.3.html) — POSIX-style case-insensitive string comparison.
- [Microsoft Learn: Generic-text mappings in tchar.h](https://learn.microsoft.com/en-us/cpp/text/generic-text-mappings-in-tchar-h?view=msvc-170) — Windows generic-text compatibility macros.