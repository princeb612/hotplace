# nostd Binary and Range Utilities

This group contains low-level value/range helpers used by the rest of the SDK.

## Binary

`binary.hpp` / `binary.cpp` and `binaries.hpp` provide binary-oriented container/conversion helpers. They are used where a byte sequence needs utility operations without introducing a higher-level protocol type.

## Ranges and capacity

- `range.hpp` — range representation and iteration helpers
- `range_set.hpp` — normalized sets of ranges and interval operations; see [range_set](range_set.md)
- `capacity.hpp` — capacity-related helpers
- `bit_set.hpp` — bit-level set representation

The range facilities are particularly relevant to pattern matching and span-based processing.

## Related tests

- `testcase_binary.cpp`
- `testcase_bitset.cpp`
- `testcase_range.cpp`
