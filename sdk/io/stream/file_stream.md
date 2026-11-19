## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# File Stream

## 1. Role

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

## 2. Data Model
### Stream state

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

## 3. Behavior Model

### Memory-mapped access lifecycle

Memory mapping is explicit rather than an automatic property of `file_stream`. `begin_mmap()` rejects a closed stream and does nothing when already mapped. Empty-file behavior differs by platform: the Linux implementation returns success without creating a mapping when the file size is zero; the Windows implementation has no corresponding zero-size guard and proceeds to `CreateFileMapping`, which can fail for an empty file.

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

The mapping is useful when a caller needs random access to the entire file as a byte array. The direct testcase writes through the mapped view, unmaps it, seeks to the beginning, and verifies the data through `read()`.

### Read/write and formatting paths

```text
stream API: read() / write() / seek() / truncate()

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

`printf()` and `vprintf()` reuse the formatting/buffer machinery from `sdk/base/stream`, rather than calling the operating-system formatted I/O API directly. The ordinary stream API and mapped access are complementary ways to access the same file, but their active-state requirements differ.

### Concrete caller path: mapped write followed by ordinary read

The stream testcase uses the public file-stream API to show why the mapping lifetime is explicit. The following is reduced from `test/testcase/io/stream/testcase_filestream.cpp`:

```cpp
#include <hotplace/sdk/io/stream/file_stream.hpp>

file_stream fs;
return_t ret = fs.open("testfile", open_write);
if (errorcode_t::success == ret) {
    fs.truncate(1024);
    ret = fs.begin_mmap();
    if (errorcode_t::success == ret) {
        byte_t* bytes = fs.data();
        *reinterpret_cast<uint32*>(bytes) = 0x12345678;
        fs.end_mmap();

        fs.seek(0, FILE_BEGIN);
        uint32 value = 0;
        size_t size_read = 0;
        fs.read(&value, sizeof(value), &size_read);
        // The testcase asserts value == 0x12345678.
    }
}
```

The mapped pointer is used only between `begin_mmap()` and `end_mmap()`; the later read uses the ordinary stream interface. This testcase verifies the first written integer, not every byte in the mapped region or all platform-specific mapping and locking behaviors.

### Open flags

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

### Basic file lifecycle

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

`close()` also releases an active mapping and unlocks the file where the platform implementation acquired a lock. Linux releases either shared or exclusive `flock`; Windows unlocks only the exclusive `LockFileEx` path. The Windows `flag_share_flock` branch is empty, so shared locking is not implemented there.

### Platform implementation

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

The narrow-character `open(const char*, ...)` path converts to a wide string and delegates to the Windows wide-character overload. The Windows wide-character overload acquires an exclusive lock with `LockFileEx` when requested, but its `flag_share_flock` branch does nothing. The return value from `LockFileEx` is not checked.

### Current scope

There is currently one substantive concrete implementation in this directory: `file_stream`.

`string.hpp` is only a placeholder and does not justify a separate module record yet. Likewise, `types.hpp` only provides declarations/types shared by the directory and does not represent an independent feature.

If additional concrete stream types are introduced later, they should get their own module records rather than expanding this document indefinitely.

### Source-level evidence

The platform wrappers expose the same method names, but several operational details are not equivalent:

- **Linux write positioning:** `open()` uses `O_APPEND` whenever `open_write` is selected. Consequently, `seek()` changes the read position but does not make subsequent writes overwrite at that position; writes remain append-oriented. The Windows open path uses ordinary `GENERIC_WRITE` access and does not add an equivalent append flag.
- **Lock status:** Linux ignores the return value from `flock()`, and Windows ignores the return value from `LockFileEx()`. A successful `open()` result therefore does not prove that a requested lock was acquired.
- **Read status on Windows:** `ReadFile()` returns a Boolean result, but the current implementation checks `rc == -1`. A failed call returns `FALSE` (zero), so this check does not detect the failure and the wrapper can report success with an unsuccessful/short read. The Windows `begin_mmap()` path also does not check whether `MapViewOfFile()` returned a non-null view; it can leave `_file_data` null while returning the success status from `CreateFileMapping()`.
- **Formatting status:** both platform implementations call `write()` from `printf()` / `vprintf()` without assigning or checking its return value. A formatting call can therefore report success even when the file write failed.
- **Flush status:** Linux `flush()` is an unconditional success no-op. Windows also returns success without checking the OS result; on the mapped path it calls `FlushViewOfFile(_file_handle, 0)`, passing the file handle rather than the mapped view address `_file_data`. Do not rely on mapped flush through this wrapper until corrected.

These are source-level observations; they were not reproduced as runtime failures during this documentation audit.

### Test coverage

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

### Related tests

- `test/testcase/io/stream/testcase_filestream.cpp`
- `test/testcase/io/sample.cpp`
- `test/testcase/io/sample.hpp`

## 4. Relationships
### Related modules

- `sdk/base/stream/` — common stream, buffer and formatting layer
- `sdk/io/string/` — I/O string facilities
- `sdk/io/basic/` — protocol-oriented binary I/O helpers

### Implementation source navigation
- `sdk/io/stream/file_stream.hpp`
- `sdk/io/stream/linux/file_stream.cpp`
- `sdk/io/stream/windows/file_stream.cpp`
- `sdk/io/stream/stream.hpp`
- `sdk/base/stream/stream.hpp`
- `sdk/base/stream/basic_stream.hpp`
- `sdk/base/stream/lowlevel/bufferio.hpp`
