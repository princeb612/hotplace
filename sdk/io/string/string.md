# I/O String Utilities

The `string.hpp` / `string_charset.cpp` pair provides small string-processing helpers intended for I/O-facing code. It is not the general-purpose string module; that role belongs to `sdk/base/string/`.

## Tokenization

Two related helpers are provided:

- `tokenize(source, tokens, pos, mode)` — extracts the next token from a string while advancing the caller-owned position.
- `gettoken(source, token, index, value)` — obtains a token by index and is implemented in terms of `tokenize`.

`token_quoted` is available as a mode flag for quoted-token handling. The implementation searches for delimiter characters and maintains the current position so callers can iterate through a sequence without building a separate token container.

The implementation exists for both narrow and wide string forms under the corresponding character-set build configuration.

## Character-set/platform variants

The Windows-specific API provides:

- `A2W()` — multibyte string to `std::wstring`
- `W2A()` — wide string to `std::string`

Both use the Windows `MultiByteToWideChar` / `WideCharToMultiByte` APIs and accept a Windows code page. The overloads returning `return_t` also report invalid input parameters.

The Unicode implementation reuses the same tokenization implementation by compiling `string_charset.cpp` under the Unicode build macros.

## Relationship to base/string

The similarly named `gettoken`/`tokenize` helpers also appear in the base string area and in existing base-string tests. The important distinction for this directory is that `sdk/io/string` is the I/O-layer facility and also owns the platform-specific conversion files and URL support included by the I/O library.

## Related source

- `sdk/io/string/string.hpp`
- `sdk/io/string/string_charset.cpp`
- `sdk/io/string/windows/mbs2wcs.cpp`
- `sdk/io/string/windows/wcs2mbs.cpp`
- `sdk/io/string/unicode/string_wcs.cpp`

## Related tests / usage

There is no dedicated I/O-string testcase directory. Tokenization is part of the shared utility surface, while the URL-facing portion is exercised by HTTP tests. Windows character conversion is platform-specific and is compiled as part of the I/O library.
