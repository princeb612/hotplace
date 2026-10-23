## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# HTTP protocol lookup resources

## 1. Role

The `resource/` directory supplies the protocol-specific lookup tables behind `http_resource`, declared in the parent directory as `http_resource.hpp`. These tables turn numeric HTTP status codes, methods, frame types, flags, SETTINGS identifiers, and protocol error codes into readable names, and expose the HPACK/QPACK static-table entries for enumeration.

This is internal lookup/diagnostic data. It does not parse HTTP messages, implement frame state machines, or provide the mutable per-connection compression tables.

## 2. Data Model

```text
http_resource (singleton, declared in ../http_resource.hpp)
  ├─ HTTP/1.x
  │    ├─ status code -> reason phrase
  │    └─ method enum -> method name
  ├─ HTTP/2
  │    ├─ frame type / flags -> names
  │    ├─ SETTINGS id -> name
  │    ├─ error code -> name
  │    └─ HPACK static-table enumeration
  └─ HTTP/3
       ├─ stream type / frame type -> names
       ├─ SETTINGS id -> name
       ├─ error code -> name
       └─ QPACK static-table enumeration
```

The singleton stores these entries in maps keyed by the corresponding numeric code or method enum. The implementation is split by protocol generation:

- `http_resource_http1.cpp` populates status phrases and method names.
- `http_resource_http2.cpp` populates HTTP/2 frame names, flag names, SETTINGS names, error names, and HPACK static-table data.
- `http_resource_http3.cpp` populates HTTP/3 stream/frame names, SETTINGS names, error names, and QPACK static-table data.

The `http_static_table_entry` structure contains an index and a header name/value pair. It is lookup data for enumeration; it is distinct from a connection's mutable HPACK/QPACK dynamic table.

## 3. Behavior Model

### Lazy initialization and lookup

```text
http_resource::get_instance()
  -> load_resources()
  -> if status-code table is empty:
       lock
       -> check again
       -> doload_resources()
            -> doload_resources_h1()
            -> doload_resources_h2()
            -> doload_resources_h3()
  -> return singleton
```

The initial load uses the status-code table as its initialization guard. Once initialization runs, the protocol-specific loaders populate their maps. Lookup methods then return the stored name/phrase for a code; static-table accessors enumerate entries through a callback and expose the table size. These methods provide readable metadata to protocol code and diagnostics, while actual parsing/encoding decisions remain in the HTTP/1.x, HTTP/2, HPACK, HTTP/3, and QPACK implementations.

## 4. Relationships
- `../http_resource.hpp` — singleton interface, lookup methods, and map declarations.
- `http_resource_http1.cpp` — HTTP status phrases and method names.
- `http_resource_http2.cpp` — HTTP/2 frame/flag/SETTINGS/error names and HPACK static-table entries.
- `http_resource_http3.cpp` — HTTP/3 stream/frame/SETTINGS/error names and QPACK static-table entries.
- [HTTP overview](../README.md) — common module boundaries.
- [HTTP/2](../http2/README.md), [HPACK](../hpack/README.md), [HTTP/3](../http3/README.md), and [QPACK](../qpack/README.md) — protocol implementations that consume related metadata.

## 5. References
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 7541 — HPACK](https://www.rfc-editor.org/rfc/rfc7541)
- [RFC 9204 — QPACK](https://www.rfc-editor.org/rfc/rfc9204)
- [HTTP/3 parameters](https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml)
