## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# zlib Compression

## 1. Role

`sdk/io/basic/zlib.*` wraps zlib's compression and decompression API in hotplace overloads that accept byte buffers, `binary_t`, and `stream_t`. It is a primitive wrapper: HTTP or JOSE code chooses when compression applies and which framing is required.

## 2. Data Model
### Framing selection

`zlib_windowbits_t` selects the format passed to zlib:

| hotplace option | zlib window bits | Representation |
|---|---:|---|
| `windowbits_compress` | `MAX_WBITS` | zlib wrapper around DEFLATE |
| `windowbits_deflate` | `-MAX_WBITS` | raw DEFLATE stream |
| `windowbits_gzip` | `MAX_WBITS + 16` | gzip wrapper around DEFLATE |

The distinction is observable on the wire: raw DEFLATE, zlib-wrapped data, and gzip are not interchangeable merely because the compression algorithm is related.

### API families

`zlib_deflate()` and `zlib_inflate()` are overloaded for:

- `binary_t` input/output;
- raw `byte_t*` plus size;
- `stream_t` input and/or output;
- `FILE*`-oriented `zlib_def()` and `zlib_inf()` helpers.

The memory/stream overloads clear the destination before producing a new result and append chunks from a fixed 1 KiB working buffer as zlib reports output.

## 3. Behavior Model
The wrappers initialize a `z_stream`, choose `windowBits` from the requested mode, run `deflate()` or `inflate()`, and release zlib state with `deflateEnd()` / `inflateEnd()`. Raw pointer overloads reject a null input pointer; stream-output overloads also reject a null output stream.

These functions are intentionally lower-level than content negotiation. A caller must select a mode compatible with the data being decoded and handle the returned status. The implementation should not be read as a promise that every malformed input or every zlib terminal condition receives exhaustive protocol-level diagnostics; those semantics belong to the actual wrapper implementation and its callers.

### Source-level evidence
No dedicated zlib testcase is present under `test/testcase/io/basic` in this source tree. The integration paths select a mode at the call site: HTTP response compression can use raw DEFLATE or gzip framing, while JOSE `zip: DEF` uses raw DEFLATE. Trace the caller's content/algorithm decision, then follow the selected `zlib_windowbits_t` into `zlib.cpp`. These are integration paths, not direct unit tests for every wrapper overload.

## 4. Relationships
- `sdk/base/stream/` — stream abstraction used by stream-oriented overloads.
- `sdk/net/http/http_response.cpp` — HTTP content compression consumer.
- `sdk/crypto/jose/json_object_encryption.cpp` — JOSE `DEF` compression consumer.

### Implementation source navigation

- `sdk/io/basic/zlib.hpp/.cpp`

## 5. References

- RFC 1951 — DEFLATE Compressed Data Format Specification.
- RFC 1952 — gzip file format.
- RFC 7520 §5.9 — JOSE compressed content example (`zip: DEF`).
- RFC 2616 §3.5 — historical HTTP/1.1 content-coding context cited by the source.
