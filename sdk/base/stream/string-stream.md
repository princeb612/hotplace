# String Streams

The stream layer includes `ansi_string` and `wide_string` implementations for string-oriented stream behavior.

`ansi_string` extends `stream_t` and adds string operations such as find, replace, cut, trim and line extraction. The Unicode implementation provides the corresponding wide-string behavior.

This is distinct from `sdk/base/string`: these classes combine string manipulation with the stream/buffer abstraction.

## Related source

- `ansi_string.hpp/.cpp`
- `unicode/wide_string.hpp/.cpp`
- `unicode/bufferio_wcs.cpp`
- `unicode/printf_wcs.cpp`

## Related tests

- `test/testcase/base/stream/testcase_stream.cpp`
