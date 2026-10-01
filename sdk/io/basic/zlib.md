# zlib Compression

## Role

`sdk/io/basic/zlib.*` provides a thin hotplace-facing wrapper around zlib compression and decompression.

The wrapper keeps the same operation available for `binary_t`, raw buffers and `stream_t` destinations/sources.

```text
input
  |
  +--> binary_t
  +--> raw buffer
  +--> stream_t
          |
          v
   zlib_deflate / zlib_inflate
          |
          v
       output
```

## Window modes

`zlib_windowbits_t` selects the wire format passed to zlib:

- `windowbits_compress` — ordinary zlib wrapper using `MAX_WBITS`
- `windowbits_deflate` — raw DEFLATE, corresponding to RFC 1951
- `windowbits_gzip` — gzip wrapper, corresponding to RFC 1952

This distinction matters because the compressed byte stream format is not identical even though all three use the DEFLATE algorithm internally.

## API shape

The module exposes `zlib_deflate()` and `zlib_inflate()` overloads for:

- `binary_t`
- `byte_t* + size`
- `stream_t`

and supports both memory-oriented and stream-oriented output.

The implementation uses a fixed working buffer and repeatedly calls the zlib API until the operation reaches its terminal result.

## Protocol relationship

The header references several uses of compressed content, including:

- RFC 1951 — DEFLATE
- RFC 1952 — gzip
- RFC 2616 — HTTP content codings
- RFC 7520 — JOSE compressed content (`zip` = `DEF`)

The basic module only provides the compression primitive wrapper. Protocol-specific negotiation or header semantics belong to the higher-level protocol modules.

## Related source

- `sdk/io/basic/zlib.hpp`
- `sdk/io/basic/zlib.cpp`

## Current test coverage

No dedicated `test/testcase/io/basic` zlib testcase is present in the rev1095 tree inspected for this document. The module is therefore recorded here as an implemented utility rather than implying a dedicated testcase that does not currently exist.
