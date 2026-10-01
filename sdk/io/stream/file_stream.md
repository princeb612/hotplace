# File Stream

## Role

`file_stream` is the concrete file-backed implementation of the common `stream_t` interface.

Its purpose is to give higher-level hotplace code one file API while keeping Linux and Windows system calls behind platform-specific source files.

```text
caller
  │
  ▼
file_stream
  │
  ├── ordinary read/write
  ├── seek/truncate
  ├── printf/vprintf
  └── memory mapping
       │
       ├── Linux: POSIX fd + mmap
       └── Windows: HANDLE + CreateFileMapping/MapViewOfFile
```

## Open flags

`filestream_flag_t` describes the file-open policy.

The basic flags are:

- `flag_write`
- `flag_exclusive_flock`
- `flag_create_if_not_exist`
- `flag_create_always`
- `flag_share_flock`

Convenience combinations include:

- `open_existing` / `open_readonly`
- `open_create` / `open_write`
- `open_create_always`
- `exclusive_read`
- `exclusive_write`
- `exclusive_create`
- `share_read`
- `share_write`
- `share_create`

The abstraction deliberately keeps these policies at the hotplace API boundary instead of exposing POSIX/Win32 flags to callers.

## Basic file lifecycle

The normal lifecycle is:

```text
file_stream fs;

fs.open(filename, mode)
        │
        ├── read/write/printf
        ├── seek()
        ├── truncate()
        └── begin_mmap() / end_mmap()
        │
        ▼
fs.close()
```

`close()` also releases an active mapping and platform-specific file lock.

## Platform implementation

### Linux

`linux/file_stream.cpp` uses:

- `open`
- `read`
- `write`
- `close`
- `lseek`
- `ftruncate`
- `fstat`
- `flock`
- `mmap` / `munmap`

The mapped view is exposed through `data()` after `begin_mmap()`.

For a writable file, the mapping is created with `PROT_WRITE` and `MAP_SHARED`, so modifications to the mapped region are backed by the file.

### Windows

`windows/file_stream.cpp` uses the corresponding Win32 facilities:

- `CreateFileW`
- `ReadFile` / `WriteFile`
- `CloseHandle`
- `SetFilePointer`
- `SetEndOfFile`
- `GetFileInformationByHandle`
- `LockFileEx` / `UnlockFileEx`
- `CreateFileMapping`
- `MapViewOfFile` / `UnmapViewOfFile`
- `FlushFileBuffers` / `FlushViewOfFile`

The narrow-character `open(const char*, ...)` path converts to a wide string and delegates to the Windows wide-character overload.

## Memory mapping

Memory mapping is an explicit operation rather than an automatic property of `file_stream`.

```text
open()
  │
  ▼
begin_mmap()
  │
  ├── data() → mapped file bytes
  └── size() → file size
  │
  ▼
end_mmap()
```

`begin_mmap()` rejects a closed stream and does nothing when the file is empty or already mapped.

The mapping is useful when a caller needs random access to the entire file as a byte array. The direct testcase uses exactly this path.

## Read/write versus mapped access

The class therefore supports two different access styles:

```text
stream API
  ├── read()
  ├── write()
  ├── seek()
  └── truncate()

mapped API
  ├── begin_mmap()
  ├── data()
  └── end_mmap()
```

They are complementary. The testcase writes through the mapped view, unmaps it, seeks to the beginning, and verifies the data through `read()`.

## Formatting output

`printf()` and `vprintf()` do not call the operating-system formatted I/O API directly.

Instead:

```text
printf / vprintf
       │
       ▼
    bufferio
       │
       ▼
   formatted bytes
       │
       ▼
    write()
       │
       ▼
      file
```

This reuses the formatting/buffer machinery already provided by `sdk/base/stream`.

## Stream state

`file_stream` exposes:

- `is_open()`
- `is_mmapped()`
- `empty()`
- `occupied()`
- `size()`
- `data()`
- `get_stream_type()`

The stream type is reported as `stream_type_t::file`.

`data()` is meaningful for the active memory-mapped view; ordinary file access should use `read()`/`write()`.

## Test coverage

`test/testcase/io/stream/testcase_filestream.cpp` currently exercises:

1. `open(..., open_write)`
2. `truncate(1024)`
3. `begin_mmap()`
4. writing data directly through `data()`
5. `end_mmap()`
6. `seek(0, FILE_BEGIN)`
7. `read()`
8. verification of the first written value
9. cleanup of the temporary file

The test is therefore also a compact example of the intended mmap/read workflow.

## Related source

- `sdk/io/stream/file_stream.hpp`
- `sdk/io/stream/linux/file_stream.cpp`
- `sdk/io/stream/windows/file_stream.cpp`
- `sdk/io/stream/stream.hpp`
- `sdk/base/stream/stream.hpp`
- `sdk/base/stream/basic_stream.hpp`
- `sdk/base/stream/lowlevel/bufferio.hpp`

## Related tests

- `test/testcase/io/stream/testcase_filestream.cpp`
- `test/testcase/io/sample.cpp`
- `test/testcase/io/sample.hpp`

## Related modules

- `sdk/base/stream/` — common stream, buffer and formatting layer
- `sdk/io/string/` — I/O string facilities
- `sdk/io/basic/` — protocol-oriented binary I/O helpers

## Current scope

There is currently one substantive concrete implementation in this directory: `file_stream`.

`string.hpp` is only a placeholder and does not justify a separate module record yet. Likewise, `types.hpp` only provides declarations/types shared by the directory and does not represent an independent feature.

If additional concrete stream types are introduced later, they should get their own module records rather than expanding this document indefinitely.
