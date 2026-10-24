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

# Decoder Stream

## 1. Role

### Introduction

`decoder_stream` incrementally decodes input that may arrive across arbitrary chunk boundaries. It preserves incomplete decoding state and delegates complete units to the corresponding decoder.

The implemented streaming paths are Base16, Base64/Base64URL, and HTTP/2 Huffman. Although the enum/header describes RFC-style Base16, the current `write()` implementation returns `not_supported` for that selector.

## 2. Data Model

### Input, output, and retained state

- `_encoding` selects the decoding path.
- `_buffer` accumulates decoded bytes returned by `data()`.
- `encbuf_t` retains incomplete textual units: up to one trailing Base16 character or up to three trailing Base64/Base64URL characters.
- `_huffbuf` stores pending Huffman bit state between calls.
- `_maxsize` defaults to 32 KiB and is configurable through `set_maxsize()`. The implementation checks `_buffer.size() + input size`; this is the actual guard, not a general promise that every intermediate or final representation is bounded identically.

The class accepts raw character/byte ranges and provides `add()` and stream-style operators as convenience wrappers around `write()`.

## 3. Behavior Model

### Chunk processing

```text
write(encoded chunk)
      │ validate input and apply size check
      ▼
switch (_encoding)
  ├── Base16 ───────────────► decode complete pairs; retain odd tail
  ├── Base64 / Base64URL ───► decode complete 4-char groups; retain suffix
  ├── HTTP/2 Huffman ───────► decode through fixed table and retain bit state
  └── Base16 RFC ───────────► not_supported
                                      │
                                      ▼
                              append decoded bytes
```

If a prior chunk left a partial Base16/Base64 unit, the next chunk first fills that unit. The decoder then processes the remaining complete groups and saves any incomplete suffix. Huffman input follows a separate bit-oriented path through `http_huffman_coding`.

### Finalization

`data()` invokes `flush()` and then returns the accumulated `_buffer`. The current implementation handles the retained state by encoding type:

- Base16 decodes a pending unit only when two characters are retained.
- Base64/Base64URL discard a one-character suffix; other non-empty suffixes are passed to the Base64 decoder.
- HTTP/2 Huffman checks the remaining padding state and may return `bad_data` from `flush()`.

Important API detail: `data()` returns the byte buffer, not the status returned by its internal `flush()`. Callers needing explicit error handling should check each `write()` result and should not treat a returned buffer alone as proof that finalization succeeded.

### Concrete caller path: chunked decode and final retrieval

The Base64 testcase feeds encoded text in chunks, then obtains the accumulated bytes from the decoder:

```cpp
decoder_stream decoder(encoding_t::encoding_base64);
return_t ret = decoder.write(encoded.data(), 2);
if (errorcode_t::success == ret) {
    ret = decoder.write(encoded.data() + 2, encoded.size() - 2);
}
if (errorcode_t::success == ret) {
    binary_t decoded = decoder.data();
}
```

The split at two characters deliberately cuts across a four-character Base64 group. The decoder retains the suffix and combines it with the next write. Note the API caveat above: `data()` returns the buffer, not the status from its internal `flush()`; checking `write()` is necessary but is not a separate assertion that every final suffix was valid. The full testcase uses many chunk sizes and compares the decoded output with the original byte sequence.

Source: `test/testcase/encode/testcase_base64.cpp`.

## 4. Relationships

- `base16.*` and `base64.*` provide the conversion routines used by this stream.
- `http_huffman_coding.*` supplies the protocol-specific Huffman decoder.
- `encoder_stream` is the corresponding stateful encoding layer.
- `test/testcase/encode/testcase_base16.cpp`, `testcase_base64.cpp`, and `testcase_huffman.cpp` provide source-level coverage for chunked decoding, including inputs split at different chunk sizes.
