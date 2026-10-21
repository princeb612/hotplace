## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# I/O String Utilities

## 1. Role

The `string.hpp` / `string_charset.cpp` pair provides lightweight tokenization helpers for I/O-facing code. The directory also declares URL helpers and Windows character-conversion functions, but those behaviors are documented in more detail in [url.md](url.md) and in the platform source files.

## 2. Data Model
### Tokenization

- `tokenize(source, tokens, pos, mode)` extracts the next token and advances the caller-owned `pos`. The `token_quoted` mode flag enables quoted-token handling.
- `gettoken(source, token, index, value)` retrieves a token by index and is implemented in terms of `tokenize()`.

The caller controls iteration state. The helper is convenient for simple delimiter-based formats, but it is not a lexer with grammar rules, escaping semantics, or error recovery.

### Character-set variants

- Narrow-string implementations are in `string_charset.cpp`.
- Windows builds expose `A2W()` and `W2A()` helpers, with overloads returning `return_t` for reporting invalid parameters. They use `MultiByteToWideChar()` and `WideCharToMultiByte()` with a selected Windows code page.
- `unicode/string_wcs.cpp` provides the Unicode build variant of the string helper implementation.

## 3. Behavior Model
The tokenization API returns token text by value and uses the mutable position argument to let the caller continue scanning. `gettoken()` offers indexed access but is documented in the header as simple rather than efficient; repeated indexed requests may redo tokenization from the beginning.

Character conversion is platform-dependent. Do not assume the Windows-only `A2W()` / `W2A()` declarations are available in non-Windows builds, and do not treat a successful conversion as a guarantee that every source byte sequence is valid in every code page.

### Source-level evidence
`test/testcase/io/string/testcase_string.cpp` tests `split_url()` rather than directly asserting `tokenize()` or `gettoken()`. The header `sdk/io/string/string.hpp` contains examples for tokenization, including `gettoken("key=item1|value1|link1", "=|", 0, value)` and a position-driven `tokenize()` loop. These header examples explain the API shape, but they are not substitutes for a dedicated runtime test of every tokenization mode.

To see the shared string helpers in an integration context, follow URL decomposition in `url.cpp`; the URL implementation uses the base regex/stream facilities and shares this directory's public header.

## 4. Relationships
- `sdk/base/string/` — general-purpose string facilities; keep the two similarly named modules distinct.
- `sdk/io/string/url.cpp` — URL processing functions declared alongside the tokenization APIs.
- `sdk/base/pattern/` and `sdk/base/stream/` — regex and output-stream facilities used by URL processing.

### Implementation source navigation
### Source

- `sdk/io/string/string.hpp`
- `sdk/io/string/string_charset.cpp`
- `sdk/io/string/unicode/string_wcs.cpp`
- `sdk/io/string/windows/mbs2wcs.cpp`
- `sdk/io/string/windows/wcs2mbs.cpp`
- `test/testcase/io/string/testcase_string.cpp`
