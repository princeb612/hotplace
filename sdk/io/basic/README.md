## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1107                     │
│ Source basis: Revision 1107                   │
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

### Shared data concepts

The components do not share one universal I/O object. Their main intermediate representations are:

| Data | Meaning | Produced or consumed by |
|---|---|---|
| Ordered `payload_member` sequence | Field layout plus current field values, group membership, and optional length references | `payload` |
| `oid_t` (`std::vector<uint32>`) | Numeric OID arcs, not BER/DER bytes | OID conversion and dictionary lookup |
| `oid_metadata` | Dictionary result containing a name and description | `oid_dictionary` |
| Jansson `json_t*` | Parsed JSON value tree with Jansson reference-counted ownership | `json_open_stream()`, `json_open_file()` |
| Byte buffer / `stream_t` | Compressed or decompressed content bytes | `zlib_deflate()`, `zlib_inflate()` |
| `zlib_windowbits_t` | Framing choice used to initialize zlib's DEFLATE state | zlib wrappers |

These representations are intentionally distinct: an OID node vector is not an encoded OID, a JSON tree is not owned by a hotplace wrapper type, and the zlib framing option is separate from the payload being compressed.

## 3. Behavior Model

### Component flow map

```text
field definitions + field values
            │
            ▼
      payload / payload_member
            │ write                         read
            ▼                                ▲
       binary_t  ◄── ordered fields ─────────┘

OID dotted text ──► numeric token scan ──► oid_t ──► dictionary trie lookup
ASN.1 braced text ─► decimal token scan ──► oid_t

JSON text or file ──► Jansson parser ──► json_t* ──► caller's JSON operations
                                           │
                                           └── json_decref() when finished

input bytes + framing mode ──► zlib state ──► 1 KiB output chunks ──► output bytes/stream
```

### Flow boundaries

- **Payload:** member order defines the binary field order. Group state and length references affect which bytes are consumed or emitted; specialized `payload_encoded` fields delegate their internal format to the implementing type.
- **OID:** conversion produces numeric nodes. Dictionary lookup is a subsequent operation, and ASN.1 BER/DER encoding belongs to `sdk/io/asn.1`.
- **JSON:** the wrapper validates its output/input pointers, delegates parsing to Jansson, returns a hotplace status, and leaves successful JSON-reference ownership with the caller.
- **Compression:** the caller chooses zlib-wrapped, raw DEFLATE, or gzip framing. The wrapper resets its destination and accumulates generated output; it does not choose a format from HTTP or JOSE metadata itself.


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

- [RFC 1951 — DEFLATE Compressed Data Format](https://www.rfc-editor.org/rfc/rfc1951).
- [RFC 1952 — gzip file format](https://www.rfc-editor.org/rfc/rfc1952).
- [RFC 7520 — JOSE examples](https://www.rfc-editor.org/rfc/rfc7520), including the zip DEF compressed-content example.
- [RFC 2616 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc2616) — historical content-coding context used by source comments.
- [Jansson documentation](https://jansson.readthedocs.io/en/latest/) — JSON parsing library included through jansson.h.
