## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1107                     │
│ Source basis: Revision 1107                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```
# I/O Stream

## 1. Role

`sdk/io/stream` provides the file-backed implementation of the common stream interface. The substantive feature in this directory is `file_stream`; platform-specific source files hide the differences between POSIX file descriptors and Win32 handles/mappings.

This directory is distinct from `sdk/base/stream`, which provides in-memory streams, buffers, and formatting machinery. `sdk/io/stream` uses that common interface at a file boundary.

## 2. Data Model

- `file_stream.hpp` declares the public class and open flags.
- `stream.hpp` contains file open/seek constants and related flags.
- `types.hpp` contains shared declarations.
- `string.hpp` is currently a placeholder rather than an independent concrete stream implementation.

The details of mapping, flags, lifecycle, and the platform split are described in [file_stream.md](file_stream.md).

## 3. Behavior Model

### File-stream operation path

```text
caller
  │
  ▼
file_stream (common API)
  ├── open / close
  ├── read / write / seek / truncate
  ├── printf / vprintf ──> base stream buffer/formatting
  └── begin_mmap / data / end_mmap
          │
          ├── linux/file_stream.cpp   POSIX fd + mmap + flock
          └── windows/file_stream.cpp Win32 HANDLE + file mapping + locks
```


A `file_stream` owns an open platform file resource and may also own a memory mapping and a platform lock. `close()` is the boundary that releases these resources; mapped access should be treated as valid only while the mapping is active. Ordinary file reads and writes use the stream API, while `data()` is intended for direct access to the mapped view.

`printf()` and `vprintf()` reuse `bufferio` from `sdk/base/stream`, format into bytes, and then write those bytes to the file. This is a concrete example of the division between base stream facilities and OS-backed I/O.

### File and mapping access

The important boundary is external resource access: the file-stream implementation adapts the common stream interface to platform file operations and, where supported, mapped access. A caller may cross between mapped access and ordinary stream reads, so the file handle, mapping, seek position, and close path must be understood from the concrete implementation.

## 4. Relationships
- `sdk/base/stream/` — common `stream_t`, buffers, and formatting.
- `sdk/io/basic/` — binary payload helpers that can use common stream abstractions.
- `sdk/io/string/` — URL and textual helpers; not the same module as the placeholder `string.hpp` in this directory.
- `test/testcase/io/stream/` — direct file-stream test.

The implementation is split across `file_stream.hpp`, `stream.hpp`, `linux/file_stream.cpp`, and `windows/file_stream.cpp`; these files are linked from the [stream directory](./) and should be read when checking platform-specific lifecycle details.

## 5. Developer Notes
- Keep the boundary with `sdk/base/stream` explicit: do not describe in-memory `basic_stream` behavior as if it were implemented by `file_stream`.
- If a second concrete stream type is added, give it a separate module document instead of turning this directory README into an exhaustive class reference.
