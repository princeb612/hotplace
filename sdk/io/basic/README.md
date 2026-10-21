## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1105                     │
│ Source basis: Revision 1105                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```
# I/O Basic

## 1. Role

`sdk/io/basic` contains small, reusable helpers used at the boundary between values and I/O/protocol representations. Its scope is narrower than `sdk/base`: the main concern here is representing binary fields, converting OID text, loading JSON through Jansson, and wrapping compression operations.

The directory does not attempt to provide one universal serialization model. `payload` is a declarative description for a known binary layout; OID conversion is a text/node utility; JSON and zlib are wrappers around existing libraries.

## 2. Data Model

### Components

| Component | Main responsibility | Implementation notes |
|---|---|---|
| `payload` | Ordered field description used for writing and reading binary messages | Supports named values, groups, references, and specialized `payload_encoded` fields; see [payload.md](payload.md) |
| `oid` | Dotted decimal or ASN.1-braced OID text to integer-node vector, and node vector to dotted text | Separate from ASN.1 BER/DER encoding; see [oid.md](oid.md) |
| `zlib` | Deflate/inflate wrapper over zlib | Selects zlib-wrapped, raw DEFLATE, or gzip framing; see [zlib.md](zlib.md) |
| `json` | Parse JSON text or a file into a Jansson `json_t*` | Caller owns the resulting Jansson reference; see [json.md](json.md) |
| `types.hpp` | Shared declarations/types for this I/O area | Supporting header rather than a separate feature |

### Typical use paths

```text
protocol field layout ──> payload ──> binary_t / stream_t
OID text ───────────────> oid nodes ──> dictionary or ASN.1 encoder
JSON text/file ─────────> json_open_* ──> Jansson json_t*
content bytes ──────────> zlib_deflate / zlib_inflate ──> output bytes/stream
```

These paths are related by their use in I/O and protocol code, but they are not interchangeable abstractions.

## 3. Behavior Model

- `payload` keeps the field description and field values together so the same description can be used for encoding and decoding. Variable-size fields may use a reference to another field, and groups can enable or suppress optional portions.
- OID conversion operates on node values. It does not validate or encode every ASN.1 OBJECT IDENTIFIER rule by itself; format-specific encoding is implemented by the ASN.1 subsystem.
- `json_open_stream()` and `json_open_file()` return a Jansson object through an output pointer. A successful parse creates a reference the caller must eventually release with `json_decref()`.
- `zlib` format selection matters: zlib wrapper, raw DEFLATE, and gzip are distinct byte-stream framings even though they use DEFLATE internally.

### Representative flows

`payload` maps named members to an ordered binary layout; callers can use that layout to write or read fields through the relevant stream interface. OID dictionary lookup is a separate path: textual identifiers are resolved through the dictionary rather than encoded as ASN.1 BER/DER values here.

## 4. Relationships

- `sdk/base/basic/` — `variant` and common value representations used by payload members.
- `sdk/base/system/` — numeric and runtime helpers.
- `sdk/base/stream/` — `basic_stream`/`stream_t` support used by formatting and output paths.
- `sdk/io/system/` — shared I/O types, including the `payload_encoded` integration boundary.
- `sdk/io/asn.1/` — ASN.1 semantic and BER/DER encoding/decoding behavior.
- `sdk/crypto/jose/` and `sdk/net/http/` — concrete consumers of JSON parsing and compression.
- Implementation navigation: `payload.hpp/.cpp` and `payload_member.cpp` define the field-layout path; `oid.hpp/.cpp` and `oid_dictionary*` implement OID conversion/dictionary lookup; `zlib.hpp/.cpp` wraps compression; and `json.hpp` plus `types.hpp` provide JSON and shared declarations.

## 5. References

### Standards and external libraries

- RFC 1951 — DEFLATE Compressed Data Format.
- RFC 1952 — gzip file format.
- RFC 7520 — JOSE examples, including the `zip: DEF` compressed-content example.
- RFC 2616 — historical HTTP/1.1 content-coding context used by the source comments.
- Jansson — JSON parsing library included through `jansson.h`.

