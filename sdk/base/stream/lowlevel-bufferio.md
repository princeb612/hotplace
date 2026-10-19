## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Low-Level Buffer I/O (`bufferio`)

## 1. Role

`bufferio` is the low-level buffered storage and formatted-output helper used by the base stream layer. It manages a `bufferio_context_t` handle, accepts bytes or formatted text, and exposes operations for retrieving, comparing, searching, inserting, cutting, replacing, and clearing buffered content. It is lower-level than `basic_stream`; it is not an OS file stream.

## 2. Model

The context stores a queue of allocated blocks. Each block tracks its base address, current offset, and capacity (`limit`). The context also tracks the configured block size, padding size, total content size, flags, and a critical-section lock.

```text
caller
  | open()
  v
bufferio_context_t
  +-- block_size / pad_size / flags
  +-- bufferio_size
  +-- lock
  +-- queue of bufferio_t blocks
          | write() / printf() / vprintf()
          v
      buffered bytes
          | get() / compare() / find_*()
          | insert() / cut() / replace() / clear()
          v
      caller-visible content
```

This is a conceptual model derived from `bufferio.hpp` and `bufferio.cpp`. `get()` may return the only queued block directly; when multiple blocks exist, the implementation consolidates them into a newly allocated block and clears the old queue.

## 3. Important behavior and lifetime

- `open()` creates a context. A requested block size of zero is replaced with the default block size of 1024 bytes.
- `write()` appends bytes into blocks, allocating another block when the last block has no remaining capacity.
- `printf()` and `vprintf()` use the low-level formatting runtime and write formatted output to the context.
- `get()` returns a pointer and content size. The pointer is backed by internal storage; callers should not assume it remains stable across later mutating operations or calls that consolidate storage.
- A nonzero `pad_size` causes the implementation to maintain a block after an empty queue when `get()` is called; this is covered by a testcase that checks the returned pointer is non-null after open and after clear.
- `close()` clears the buffered blocks and destroys the context. `memzero_free` requests clearing the used bytes before a block is freed.

## 4. Example from the source tests

`test_bufferio1()` exercises formatted output and then checks content using size, search, cut, and compare operations. This excerpt illustrates the actual test's expected-value checks after writing `hello world`:

```cpp
ret = bio.printf(handle, "hello world");
_test_case.test(ret, __FUNCTION__, "printf");

bio.size(handle, &len);
_test_case.assert((11 == len), __FUNCTION__, "size");

pos = bio.find_first_of(handle, "world");
_test_case.assert((6 == pos), __FUNCTION__, "find_first_of -> %i", pos);

ret = bio.cut(handle, bio.find_first_of(handle, isspace), 1);
_test_case.test(ret, __FUNCTION__, "cut");

std::string sample("helloworld");
test = bio.compare(handle, sample.c_str(), sample.size());
_test_case.assert((true == test), __FUNCTION__, "compare");
```

This is a source excerpt, not a standalone example. It omits the earlier context creation and assumes `bio`, `handle`, `ret`, `len`, `pos`, and `test` have been declared as in the testcase.

## 5. Relationships

- `bufferio.hpp` / `bufferio.cpp` — public operations and implementation of the context and block queue.
- `printf.hpp` and `printf_charset.cpp` — low-level formatted-output runtime and character-set-specific support.
- `basic_stream.md` — higher-level in-memory stream abstraction built over stream-related utilities; do not treat the two APIs as interchangeable.
- `test/testcase/base/stream/testcase_bufferio.cpp` — `test_bufferio1()` covers edits, searches, replacement, and content comparisons; `test_bufferio2()` checks non-null returned storage with a nonzero pad size.
- `test/testcase/base/stream/testcase_bufferio.md` — describes source-level test coverage and separates it from runtime execution status.

## 6. References

- Source: `sdk/base/stream/lowlevel/bufferio.hpp`
- Implementation: `sdk/base/stream/lowlevel/bufferio.cpp`
- Formatting runtime: `sdk/base/stream/lowlevel/printf.hpp`
- Test source: `test/testcase/base/stream/testcase_bufferio.cpp`
- Directory overview: [README.md](README.md)

Revision basis: hotplace source archive, revision 1104. Runtime test results were not collected as part of this documentation pass.
