## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# `splitter`

## 1. Role

`splitter<DESCRIPTOR_T>` fragments one or more byte sequences into fixed-size output segments while preserving the identity of the source group for each fragment. It is a byte-fragmentation utility; it does not encode protocol records or decide protocol semantics.

## 2. Data Model

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

## 3. Behavior Model

The ownership rules above are central to safe use: the normal pointer overload copies its input, while `splitter_noalloc` retains a non-owning pointer. `run()` consumes the queued batch and clears the registered list after traversal. The documented boundary case uses input groups of 100, 210, and 30 bytes with an 80-byte segment size; group boundaries therefore do not coincide with output segment boundaries, and the callback's fragment/group metadata is needed to reconstruct the relationship.

### DTLS handshake fragmentation in `dtls_record_publisher::publish()`

This is a concrete consumer of `splitter`, not merely a conceptual analogy. In `session/dtls_record_publisher.cpp`, the publisher serializes each handshake, removes the ordinary handshake header, and adds the remaining body to `splitter` with a descriptor containing the handshake type and DTLS handshake sequence number. The splitter then divides the body at the configured fragment-size boundaries.

```text
TLS handshake object
       |
       v
handshake->write(dir, bin)
       |
       v
remove ordinary handshake header
       |
       v
splitter.add(body, {handshake type, handshake sequence})
       |
       v
splitter::run(callback)
       |
       +-- fragment offset + fragment length
       +-- source-group descriptor
       +-- new-segment / new-group flags
       |
       v
new DTLS record + dtls_handshake_fragmented
       |
       v
DTLS fragment header + selected body slice
```

The callback uses the descriptor to preserve the original handshake type and sequence number. `splitter_new_segment` starts a new output record; unless `dtls_record_publisher_multi_handshakes` is enabled, the publisher also treats a new source group as a record boundary. It constructs `dtls_handshake_fragmented`, calls `prepare_fragment()` with the original body size, handshake sequence, fragment offset, and fragment length, then appends that fragment to the selected record. The fragmented-handshake class deliberately disables automatic DTLS handshake-sequence control so each fragment retains the sequence assigned to its original handshake.

The fragment-size setting and the publisher's output-segment-size setting are separate: `splitter` handles handshake-body fragments, while the publisher's later output path may group/segment the resulting serialized records. This distinction is essential when reading DTLS fragmentation code.

## 4. Relationships

- `split.hpp` — lower-level `split()` overloads and boundary flags.
- `test/testcase/base/stream/testcase_stream.cpp` — [testcase notes](../../../test/testcase/base/stream/testcase_stream.md) — `test_stream_split()` exercises raw splitting and prefix/previous-fragment offset handling; `test_stream_split2()` covers descriptor-driven callbacks; `test_stream_split3()` covers multi-block segmentation. These are pointers to source-level examples, not claims about test execution status.
- `sdk/net/dtls/` — protocol code may use fragmentation concepts, but `splitter` remains protocol-agnostic.
- `sdk/net/tls/session/dtls_record_publisher.cpp` — concrete caller described above; it connects splitter callback metadata to DTLS handshake-fragment construction.
