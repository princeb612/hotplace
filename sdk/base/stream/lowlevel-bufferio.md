# Low-Level Buffer I/O

`sdk/base/stream/lowlevel` contains the implementation machinery behind formatted and character-oriented stream operations.

## Main pieces

- `bufferio.hpp/.cpp` — buffered character/binary output and input helpers
- `printf.hpp` / `printf_charset.cpp` — formatting engine and character-set variants
- Unicode counterparts under `unicode/` provide wide-character implementations
- Windows conversion helpers under `windows/` bridge ANSI and wide-character forms

This layer is intentionally below `basic_stream`: it handles the low-level formatting/buffer operations while `basic_stream` presents the SDK-facing stream abstraction.

## Related tests

- `test/testcase/base/stream/testcase_bufferio.cpp`
