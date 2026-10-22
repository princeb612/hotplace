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

# Base String Utilities

## 1. Role

The base string module provides small helpers for processing strings and bounded character buffers without requiring a stream object. The public declarations in `string.hpp` cover formatting, replacement, scanning for a character predicate or match string, and finding line boundaries. Related string-wrapper types are implemented in the same directory.

## 2. Data Model

The scanning APIs use an explicit buffer pointer and length, a starting offset, and an output break position. This makes the scan boundary part of the call rather than relying on a null terminator. `getline()` follows the same bounded-buffer shape. `format()` returns a `std::string`; `replace()` modifies its source string in place.

```text
bounded buffer + start position
          |
          +--> scan(predicate or match) --> break position
          +--> getline ------------------> line boundary

format(arguments) -----------------------> std::string
replace(source, old, new) ---------------> modified source
```

## 3. Behavior Model

### Important behavior

- `scan()` has overloads for a character predicate and a match string. Wide-character overloads are conditionally declared on Windows.
- `getline()` also has a Windows wide-character overload. Its result is a break position; callers decide how to interpret delimiters and trim content.
- `replace()` replaces within an existing `std::string`; a wide-string overload is Windows-only.
- `gettoken()` and `tokenize()` are exercised by the testcase source and should not be confused with the range-based `split_context_t` API documented in [split.md](split.md).
- These APIs do not by themselves define protocol-specific token grammar; callers supply delimiters or predicates.

### Tests

- Source: `test/testcase/base/string/testcase_string.cpp`
- Test entry: `testcase_string()`
- Relevant functions: `test_string_format()`, `test_string_gettoken()`, `test_string_getline()`, `test_string_scan()`, `test_string_scan2()`, `test_string_replace()`, `test_string_tokenize()`
- Test analysis and recorded execution result: [`README.md`](../../../test/testcase/base/string/README.md)

## 4. Relationships

- [`split.md`](split.md) describes the separate context-based splitting API.
- [`obfuscation.md`](obfuscation.md) and [`constexpr-obfuscation.md`](constexpr-obfuscation.md) cover string obfuscation, not general scanning.
- `sdk/base/stream/` provides stream and formatted-output abstractions; `sdk/io/string/` provides I/O-facing string processing. Public string declarations are in `string.hpp`.
