## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HPACK implementation

## 1. Role

`hpack` implements HPACK, the header compression format used by HTTP/2. It encodes/decodes header fields and maintains HPACK static/dynamic table state. It does not parse HTTP/2 frame boundaries, route requests, or own the network connection.

## 2. Data Model

### Encoder and table state

The principal classes are `hpack_encoder`, `hpack_static_table`, and `hpack_dynamic_table`.

| Component | Model / state |
|---|---|
| `hpack_static_table` | Protocol-defined, fixed HPACK entries |
| `hpack_dynamic_table` | Mutable entries and capacity/insertion state for the relevant HTTP/2 compression context |
| `hpack_encoder` | Indexed and literal field representations plus encoder options |
| `http2_session` | Owns the HPACK dynamic-table state used while assembling per-stream request headers |
| `http_header` | Shared HTTP header collection receiving decoded name/value fields |

The encoder uses the shared `http_header_compression` interface and common table infrastructure, but HPACK static entries and dynamic-table semantics are protocol-specific. The table state is associated with the corresponding HTTP/2 compression context; it is not a global dictionary to reuse across unrelated connections.

## 3. Behavior Model

### Encoding and decoding

HPACK can represent a field using an exact static/dynamic table index, a name reference plus a literal value, or a literal name/value. The chosen representation depends on the available entries and encoder flags. Dynamic-table insertions and evictions change the compression context, so encoded header blocks must be decoded against the matching state and in the proper order.

The HTTP/2 layer owns frame/stream boundaries: HEADERS may begin a header block and CONTINUATION may carry the remaining fragment. HPACK owns the field representation and table updates within that block. A frame is not itself a compressed field and a compressed header block is not a complete HTTP request.

```text
HTTP/2 HEADERS / CONTINUATION frames
                 │ header block fragment(s)
                 ▼
             hpack_encoder
                 ├─ HPACK static table (predefined entries)
                 ├─ HPACK dynamic table (connection compression state)
                 └─ indexed / literal field representations
                 │
                 ▼
          decoded header name/value pairs
                 │
                 ▼
            http_request headers
```

The diagram follows the decode path: `hpack_encoder` exposes both encoding and decoding operations despite its class name. The HTTP/2 session supplies the relevant dynamic-table state and adds decoded name/value pairs to the request being assembled for that stream. The diagram omits frame parsing and request-completion checks, which remain the responsibility of the HTTP/2 layer.

HPACK's dynamic table is associated with the relevant HTTP/2 compression context; do not reuse it as a generic dictionary across unrelated connections. This stateful behavior is why table updates and decoder state matter in addition to the byte-level encoder.

## 4. Relationships
- `hpack_encoder.hpp/.cpp` — field encoding and decoding.
- `hpack_static_table.hpp/.cpp`, `hpack_dynamic_table.hpp/.cpp` — HPACK-specific tables.
- [Shared compression infrastructure](../compression/README.md) — common static/dynamic table and compression interfaces.
- [HTTP/2 frames and session](../http2/README.md) — HEADERS/CONTINUATION framing and per-stream state.
- [HTTP core model](../http-core-model.md) — decoded headers become part of the shared request model.
- [QPACK](../qpack/README.md) — related goal for HTTP/3, but different wire format and state coordination.
- `test/testcase/net/hpack/testcase_huffman.cpp`, `testcase_rfc7541.cpp`, and `testvector_hpack.cpp` — source-level HPACK/Huffman vectors and assertions.

## 5. References
- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541)
