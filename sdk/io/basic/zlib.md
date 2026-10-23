## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# zlib Compression

## 1. Role

`sdk/io/basic/zlib.*` wraps zlib's compression and decompression API in hotplace overloads that accept byte buffers, `binary_t`, and `stream_t`. It is a primitive wrapper: HTTP or JOSE code chooses when compression applies and which framing is required.

## 2. Data Model

### Framing mode

`zlib_windowbits_t` selects the wrapper framing passed to zlib during initialization:

| Option | zlib `windowBits` | Data format |
|---|---:|---|
| `windowbits_compress` | `MAX_WBITS` | zlib wrapper around DEFLATE |
| `windowbits_deflate` | `-MAX_WBITS` | Raw DEFLATE stream |
| `windowbits_gzip` | `MAX_WBITS + 16` | gzip wrapper around DEFLATE |

This is a decoding/encoding parameter, not a format auto-detection result. The caller selects a mode based on the surrounding protocol or content metadata.

### Input and output representations

The API overloads accept `binary_t`, a raw byte pointer plus size, or `stream_t`; output can be a `binary_t` or `stream_t`. The separate `zlib_def()` and `zlib_inf()` functions use `FILE*` streams.

The wrapper does not preserve a higher-level message structure. It transforms a byte sequence into another byte sequence, leaving HTTP content-coding, JOSE `zip`, and message boundaries to the caller.

## 3. Behavior Model

### Working buffer and output accumulation

Each buffer-oriented operation creates a local zlib `z_stream` state and a temporary `binary_t` working buffer sized to 1 KiB. The input pointer and size are installed in `next_in` and `avail_in`; zlib writes into `next_out` up to `avail_out`. The wrapper appends newly produced bytes to the destination using the difference between `total_out` and the destination's previous size. The working buffer is temporary scratch storage; output accumulates in the caller-provided destination.


### Deflate flow

```text
zlib_deflate(mode, input, output)
          │
          ├─ raw input pointer is null ─► invalid_parameter
          ▼
clear output
          │
          ▼
initialize z_stream with input pointer / size
          │
          ▼
map mode to windowBits
          │
          ▼
deflateInit2(...)
          │
          ▼
repeat
  ├─ provide 1 KiB output buffer
  ├─ call deflate(..., Z_FINISH)
  ├─ append newly produced bytes (total_out delta)
  └─ continue while return code is Z_OK
          │
          ▼
deflateEnd() ─► return hotplace status
```

### Inflate flow

```text
zlib_inflate(mode, input, output)
          │
          ├─ raw input pointer is null ─► invalid_parameter
          ▼
clear output
          │
          ▼
initialize z_stream with input pointer / size
          │
          ▼
map mode to windowBits
          │
          ▼
inflateInit2(...)
          │
          ▼
repeat
  ├─ provide 1 KiB output buffer
  ├─ call inflate(..., Z_NO_FLUSH)
  ├─ append newly produced bytes (total_out delta)
  └─ continue while return code is Z_OK
          │
          ▼
inflateEnd() ─► return hotplace status
```

### Stream overloads and destination semantics

The overloads that write to `stream_t*` follow the same initialization, framing, chunking, and zlib-call sequence, but clear the destination stream before appending decompressed or compressed bytes. A null output stream is rejected in these overloads. Overloads that take a `stream_t const*` as input adapt its data to the byte-oriented operation.

### Status and error boundary

The buffer/stream wrappers explicitly reject null input pointers, and stream-output overloads also reject a null output stream. They clear the destination before processing, so a failed operation does not preserve the destination's previous contents.

The current implementation's hotplace status is not a detailed mapping of every zlib return code: the loop stops when the return code is no longer `Z_OK`, but the wrapper does not consistently translate zlib initialization or terminal error codes into distinct `return_t` values. Callers should therefore not interpret `success` alone as proof that every malformed compressed stream was fully validated; where correctness is security- or protocol-critical, the surrounding caller must account for the exact input and expected framing.

## 5. Relationships
- `sdk/base/stream/` — stream abstraction used by stream-oriented overloads.
- `sdk/net/http/http_response.cpp` — HTTP content compression consumer.
- `sdk/crypto/jose/json_object_encryption.cpp` — JOSE `DEF` compression consumer.

### Implementation source navigation

- `sdk/io/basic/zlib.hpp/.cpp`

## 6. References

- RFC 1951 — DEFLATE Compressed Data Format Specification.
- RFC 1952 — gzip file format.
- RFC 7520 §5.9 — JOSE compressed content example (`zip: DEF`).
- RFC 2616 §3.5 — historical HTTP/1.1 content-coding context cited by the source.
