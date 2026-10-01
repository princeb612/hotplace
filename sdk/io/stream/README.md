# I/O Stream

`sdk/io/stream` provides file-backed stream support on top of the common stream abstraction in `sdk/base/stream`.

The current implementation is intentionally small: the concrete module is `file_stream`, while `stream.hpp` defines file-open flags and the directory keeps platform-specific implementations under `linux/` and `windows/`.

## Implementation map

```text
sdk/base/stream
    │
    │ stream_t / basic stream facilities
    ▼
sdk/io/stream
    │
    ├── stream.hpp
    │     └── filestream_flag_t / FILE_* seek constants
    │
    ├── file_stream.hpp
    │     ├── file open/read/write/seek
    │     ├── mmap / file mapping
    │     ├── printf / vprintf
    │     └── stream_t interface
    │
    ├── linux/file_stream.cpp
    │     └── POSIX fd / flock / mmap
    │
    └── windows/file_stream.cpp
          └── Win32 HANDLE / LockFileEx / file mapping
```

## Documents

- [File stream](file_stream.md) — concrete `file_stream` implementation and platform split

`string.hpp` is currently only a placeholder in this directory; the actual string/stream facilities live under `sdk/io/string/` and `sdk/base/stream/`.

## Boundary with `sdk/base/stream`

This directory should not be confused with `sdk/base/stream`.

- `sdk/base/stream` provides the in-memory/string/buffer stream machinery and formatting infrastructure.
- `sdk/io/stream` adapts that stream abstraction to an operating-system file.
- `file_stream::printf()` and `vprintf()` reuse `bufferio` from the base stream layer before writing the resulting bytes to the file.

This distinction matters because many higher-level modules use `basic_stream` directly without involving a file.

## Related tests

- `test/testcase/io/stream/testcase_filestream.cpp`
- `test/testcase/io/sample.cpp` / `sample.hpp`

The testcase covers opening/creating a file, truncation, memory mapping, direct memory modification, seeking, and reading back the result.

## Related areas

- `../../base/stream/` — common stream and formatting implementation
- `../string/` — higher-level I/O string facilities
- `../basic/` — binary payload and other I/O helpers that can consume stream abstractions
