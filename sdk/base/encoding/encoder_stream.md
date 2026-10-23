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

# Encoder Stream

## 1. Role

### Introduction

`encoder_stream` provides stateful encoding when input arrives in multiple chunks or through stream-style insertion. It coordinates the encoders in this directory; it is not a separate encoding algorithm.

Supported paths include Base16, Base64, Base64URL, RFC-style Base16 encoding, and HTTP/2 Huffman coding.

## 2. Data Model

### Input, mode, and output state

- `encoding_t _encoding` selects the algorithm.
- `_buffer` accumulates textual output for Base16/Base64-family paths.
- `_bin` accumulates binary output for HTTP/2 Huffman coding.
- `encbuf_t` retains up to two pending input bytes for Base64/Base64URL.
- `bitbuf_t` accumulates Huffman code bits until a complete byte can be emitted.
- `_use_bigendian` controls the byte order used when integral values are inserted; it defaults to big-endian.
- `_maxsize` defaults to 32 KiB and is configurable with `set_maxsize()`. The implementation's size check uses the text-output buffer, so this setting should not be read as a uniform cap over every internal output path.

The stream accepts raw bytes and common hotplace containers. Integral values are converted to bytes before being passed to the selected encoder.

## 3. Behavior Model

### Chunk processing

```text
write(data, size)
      │ validate pointer and configured size check
      ▼
switch (_encoding)
  ├── Base16 ───────────────► encode this chunk
  ├── Base16 RFC ───────────► format chunk as RFC-style hex text
  ├── Base64 / Base64URL ───► complete 3-byte groups; retain tail
  └── HTTP/2 Huffman ───────► append each symbol's code bits
                                      │
                                      ▼
                               emit each full byte
```

For Base64/Base64URL, `write()` first completes a previously retained group if enough new bytes arrive, then encodes all remaining complete three-byte groups. Zero to two trailing bytes stay in `encbuf_t`.

For HTTP/2 Huffman, each input symbol is looked up in the fixed code table. Bits are appended to `bitbuf_t`; every eight bits are moved to `_bin`.

### Finalization and retrieval

`str()` calls `flush()` and returns `_buffer`; `bin()` calls `flush()` and returns `_bin`. Base64 finalization encodes any remaining input bytes. Huffman finalization pads a partial output byte with one-bits before appending it. Base16 has no pending-unit finalization.

```text
write(chunk 1) ─┐
write(chunk 2) ─┼──► persistent stream state
write(chunk n) ─┘            │
                             ▼
                       str() / bin()
                             │
                            flush
                             ▼
                       finalized output
```

## 4. Relationships

- `base16.*` and `base64.*` provide the conversion routines used by the stream.
- `http_huffman_coding.*` provides the fixed protocol table and symbol-code lookup.
- `decoder_stream` is the corresponding stateful decoding layer.
- `test/testcase/encode/testcase_base16.cpp`, `testcase_base64.cpp`, and `testcase_huffman.cpp` provide source-level coverage for chunked input and finalization; this documents test intent, not execution in this documentation task.
