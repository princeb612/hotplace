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

# Low-Level Buffer I/O (`bufferio`)

## 1. Role

`bufferio` is the low-level buffered storage and formatted-output helper used by the base stream layer. It manages a `bufferio_context_t` handle, accepts bytes or formatted text, and exposes operations for retrieving, comparing, searching, inserting, cutting, replacing, and clearing buffered content. It is lower-level than `basic_stream`; it is not an OS file stream.

## 2. Data Model

The context stores a queue of allocated blocks. Each block tracks its base address, current offset, and capacity (`limit`). The context also tracks the configured block size, padding size, total content size, flags, and a critical-section lock.

This is a conceptual model derived from `bufferio.hpp` and `bufferio.cpp`. The context stores a queue of allocated blocks, each with a base address, current offset, and capacity (`limit`). It also tracks block size, padding size, total content size, flags, and a critical-section lock.

## 3. Behavior Model

### Block and retrieval lifecycle

```text
open() ─► bufferio_context_t + block queue
                   │
        write() / printf() / vprintf()
                   ▼
              buffered blocks
                   │
        get() / compare() / find_*
                   │
        get() with multiple blocks
                   └─► consolidate into one block; clear old queue

insert() / cut() / replace() / clear() ─► mutate or reset content
```

`get()` may return the only queued block directly; when multiple blocks exist, it consolidates them into a newly allocated block and clears the old queue. The returned pointer is backed by internal storage and may become invalid after mutation or consolidation.

- `open()` creates a context. A requested block size of zero is replaced with the default block size of 1024 bytes.
- `write()` appends bytes into blocks, allocating another block when the last block has no remaining capacity.
- `printf()` and `vprintf()` use the low-level formatting runtime and write formatted output to the context.
- `get()` returns a pointer and content size. The pointer is backed by internal storage; callers should not assume it remains stable across later mutating operations or calls that consolidate storage.
- A nonzero `pad_size` causes the implementation to maintain a block after an empty queue when `get()` is called; this is covered by a testcase that checks the returned pointer is non-null after open and after clear.
- `close()` clears the buffered blocks and destroys the context. `memzero_free` requests clearing the used bytes before a block is freed.
- The `test_bufferio1()` source checks a formatted `hello world` write, the resulting length of 11, the `world` offset of 6, removal of the intervening whitespace, and comparison with `helloworld`. These assertions exercise mutation and retrieval on the same context.

## 5. Relationships

- `bufferio.hpp` / `bufferio.cpp` — public operations and implementation of the context and block queue.
- `printf.hpp` and `printf_charset.cpp` — low-level formatted-output runtime and character-set-specific support.
- `basic_stream.md` — higher-level in-memory stream abstraction built over stream-related utilities; do not treat the two APIs as interchangeable.
- `test/testcase/base/stream/testcase_bufferio.cpp` — `test_bufferio1()` covers edits, searches, replacement, and content comparisons; `test_bufferio2()` checks non-null returned storage with a nonzero pad size.
- `test/testcase/base/stream/testcase_bufferio.md` — describes source-level test coverage and separates it from runtime execution status.

## 6. References

No external references are listed.
