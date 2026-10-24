## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Base String Utilities

## 1. Role

The base string module provides small helpers for processing strings and bounded character buffers without requiring a stream object. The public declarations in `string.hpp` cover formatting, replacement, scanning for a character predicate or match string, and finding line boundaries. Related string-wrapper types are implemented in the same directory.

## 2. Data Model

The scanning APIs use an explicit buffer pointer and length, a starting offset, and an output break position. This makes the scan boundary part of the call rather than relying on a null terminator. `getline()` follows the same bounded-buffer shape. `format()` returns a `std::string`; `replace()` modifies its source string in place.

The interfaces distinguish bounded input views, returned formatted strings, and in-place mutation of an existing string.

## 3. Behavior Model

### Operation flow

```text
bounded buffer + start position
          ├─ scan(predicate or match) ─► break position
          └─ getline ─────────────────► line boundary

format(arguments) ────────────────────► std::string
replace(source, old, new) ────────────► modified source
```

### Important behavior

- `scan()` has overloads for a character predicate and a match string. Wide-character overloads are conditionally declared on Windows.
- `getline()` also has a Windows wide-character overload. Its result is a break position; callers decide how to interpret delimiters and trim content.
- `replace()` replaces within an existing `std::string`; a wide-string overload is Windows-only.
- `gettoken()` and `tokenize()` are exercised by the testcase source and should not be confused with the range-based `split_context_t` API documented in [split.md](split.md).
- These APIs do not by themselves define protocol-specific token grammar; callers supply delimiters or predicates.

## 4. Relationships

- `test/testcase/base/string/testcase_string.cpp` — `testcase_string()` exercises formatting, tokenization, line scanning, bounded scanning, and replacement; see the [testcase guide and recorded result](../../../test/testcase/base/string/README.md).
- [`split.md`](split.md) describes the separate context-based splitting API.
- [`obfuscation.md`](obfuscation.md) and [`constexpr-obfuscation.md`](constexpr-obfuscation.md) cover string obfuscation, not general scanning.
- `sdk/base/stream/` provides stream and formatted-output abstractions; `sdk/io/string/` provides I/O-facing string processing. Public string declarations are in `string.hpp`.

## 5. References

No external references are listed.
