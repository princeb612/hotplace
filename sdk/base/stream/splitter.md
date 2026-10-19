## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# `splitter`

## 1. Role

`splitter<DESCRIPTOR_T>` fragments one or more byte sequences into fixed-size output segments while preserving the identity of the source group for each fragment. It is a byte-fragmentation utility; it does not encode protocol records or decide protocol semantics.

## 2. Model

Each `add()` registers a source block and a caller-provided descriptor. `run()` walks the registered blocks and calls a callback for each fragment.

```text
add(block A, descriptor A) --+
add(block B, descriptor B) --+--> queued source groups
add(block C, descriptor C) --+             |
                                           v
                              splitter::run(callback)
                                           |
                               fixed-size boundaries
                                           |
                                           v
                         callback(data, offsets, flags, descriptor)
```

The callback receives flags, the current block pointer and size, fragment offset and size, and the descriptor associated with that block. `splitter_new_segment` marks the first fragment of a new output segment; `splitter_new_group` marks the first fragment from a source group. The default segment size is 128 bytes; `set_segment_size()` clamps values less than or equal to 1 to 2.

### Storage and lifetime model

- `add(binary_t&&, descriptor, flags)` moves the byte buffer into the splitter.
- `add(pointer, size, descriptor, flags)` normally copies the bytes into owned storage.
- With `splitter_noalloc`, the pointer overload stores the caller's pointer instead of copying. The caller must keep that memory valid through `run()`.
- The implementation guards list operations and `run()` with a critical-section guard. `run()` clears the registered list after traversal, so the object behaves as a batch collector.

## 3. Important behavior and lifetime

The ownership rules above are central to safe use: the normal pointer overload copies its input, while `splitter_noalloc` retains a non-owning pointer. `run()` consumes the queued batch and clears the registered list after traversal.

## 4. Example from the source tests

The header documents three groups with sizes 100, 210, and 30 bytes and a segment size of 80. The first group fills 80 bytes of segment 0 and contributes its remaining 20 bytes to segment 1. The next group then contributes 60 bytes to the remainder of segment 1. Thus, output segment boundaries and input group boundaries are independent.

```cpp
splitter<std::string> spl;
spl.set_segment_size(80);
spl.add(std::move(stream1), std::move(std::string("group1")));
spl.add(std::move(stream2), std::move(std::string("group2")));
auto callback = [](uint32 flags, const byte_t* stream, size_t size,
                   size_t fragment_offset, size_t fragment_size,
                   const std::string& desc) {
    // Consume the fragment; flags identify segment/group boundaries.
};
spl.run(callback);
```

This is an API-shape example, not a standalone program: `stream1` and `stream2` must be valid `binary_t` values, and production callers should handle the return value.

## 5. Relationships

- `split.hpp` — lower-level `split()` overloads and boundary flags.
- `test/testcase/base/stream/testcase_stream.cpp` — [testcase notes](../../../test/testcase/base/stream/testcase_stream.md) — `test_stream_split()` exercises raw splitting and prefix/previous-fragment offset handling; `test_stream_split2()` covers descriptor-driven callbacks; `test_stream_split3()` covers multi-block segmentation. These are pointers to source-level examples, not claims about test execution status.
- `sdk/net/dtls/` — protocol code may use fragmentation concepts, but `splitter` remains protocol-agnostic.
- `dtls_record_publisher` — explicitly referenced by the header as a related use case; inspect the call site before claiming a particular production dependency.

## 6. References

- Source: `sdk/base/stream/splitter.hpp`
- Source: `sdk/base/stream/split.hpp`
- Test examples: `test/testcase/base/stream/testcase_stream.cpp`
- Directory overview: [README.md](README.md)

External references are omitted in this pilot because the implementation and tests define the behavior directly. Add external references where they explain a non-project-specific standard or protocol.
