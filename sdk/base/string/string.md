# Base String Utilities

`string.hpp` provides low-level scanning and line/token helpers used by general SDK code.

## Main operations

- `scan()` — scan a byte/wide-character buffer from a position using a character predicate or match set
- `getline()` — locate line boundaries in a bounded buffer
- formatting helpers implemented in `format.cpp`
- string charset support in `string_charset.cpp`

The API is pointer/size oriented where appropriate, allowing callers to process buffers without first constructing higher-level stream objects.

## Related functionality

The stream layer has its own string-stream classes, while `sdk/io/string` has I/O-specific tokenization and URL processing. These should be treated as separate layers even when function names overlap.

## Tests

`testcase_string.cpp` exercises formatting, scanning, line handling and token-related behavior along with the other base-string facilities.
