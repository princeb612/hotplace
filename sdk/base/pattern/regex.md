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

# Regular expressions

## 1. Role

The regex module wraps regular-expression matching behind a small hotplace API. It returns source ranges and capture-group ranges instead of exposing backend-specific match objects. It also provides tokenization helpers used by string-processing code.

## 2. Data Model

`regex_context_t` is opaque in the header and defined in `regex.cpp`. Depending on the selected compile-time backend, it owns either a `std::regex` object or a compiled PCRE expression.

The API separates compiled-context lifetime from matching:

- `regex::open()` creates the compiled context.
- `regex::search()` finds full-match ranges, optionally beginning at a caller-supplied offset.
- `regex::close()` releases the context.
- `regex_token()` exposes matched strings or ranges.
- `regex_tokens()` exposes ranges for the full match and capture groups.

All returned offsets are source offsets represented by `range_t`, not pointers into backend-owned match objects.

## 3. Behavior Model

**`regex::open(context, expr)`**

Compiles the expression and creates the opaque context. Compilation errors are returned through the hotplace error code rather than a backend-specific exception/result object.

**`regex::search(context, input, size, tokens)`**

Starts searching from offset zero and delegates to the offset overload.

**`regex::search(context, input, size, pos, tokens)`**

Clears the output collection and searches from `pos`. For each non-empty full match it appends the corresponding source range and advances the offset. The PCRE implementation uses `PCRE_NOTEMPTY` and updates `pos` from the match offsets, avoiding repeated zero-length matches at the same position. Backend edge cases should not be assumed identical merely because the wrapper API is shared.

**`regex_token()`**

Calls the capture-aware helper and converts full-match ranges into strings or range entries, depending on the overload.

**`regex_tokens()`**

Returns a map of capture-group index to source range for each match. Group zero represents the full match; subsequent indices represent capture groups when present.

**`regex::close(context)`**

Releases the compiled backend object and its context. The caller is responsible for closing a successfully opened context after use.

The backend selection is compile-time and follows compiler support rather than runtime capability detection:

- GCC 4.9.0 and later select `std::regex`.
- Earlier GCC versions select PCRE. In particular, GCC 4.8.5's libstdc++ `<regex>` implementation is not usable by this code path; the source records unresolved references involving `regex`, `smatch`, and `sregex_iterator` that were fixed in GCC 4.9.0.
- MSVC selects `std::regex`.

On older GCC toolchains, PCRE is therefore a compatibility fallback, not an alternative chosen dynamically at runtime.

## 4. Relationships

- `sdk/base/nostd/range.hpp` — source-range representation.
- `sdk/io/string/url.cpp` — uses regex tokenization to decompose URL components.
- `test/testcase/base/pattern/testvector_regex.cpp` and `testvector_regex.yml` — regex test vectors.
- `wildcard.md` — a separate pattern language with only single-element and zero-or-more wildcard symbols.

## 5. References

- [C++ regular expressions — cppreference.com](https://en.cppreference.com/w/cpp/regex) — C++11 standard-library API and implementation context.
