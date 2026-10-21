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
# HTTP protocol stack

## 1. Role

This document explains the protocol-framing adapters that let the generic network server distinguish HTTP/1.x message boundaries from HTTP/2 connection preface and frame boundaries. It focuses on the transport-to-protocol boundary, not routing or application semantics.

## 2. Data Model

### Protocol interpretation

HTTP protocol classes derive from `network_protocol` and are used by the generic `network_protocol_group` / `network_stream` machinery from `sdk/net/server`.

```text
network bytes
    ↓
network_stream
    ↓
network_protocol_group
    ├── http_protocol  → HTTP/1.x message boundary
    └── http2_protocol → HTTP/2 preface/frame boundary
```

The protocol interpreter is responsible for recognizing the protocol and determining whether the buffered bytes are incomplete, complete, oversized, or invalid. It does not perform application routing.

### HTTP/1.x

`http_protocol::is_kind_of()` identifies the HTTP/1.x form and `read_stream()` determines the request/response boundary.

The current implementation looks for the header terminator and, when `Content-Length` is present, waits until the declared body length has also arrived.

```text
headers
  ↓
\r\n\r\n
  ↓
Content-Length ?
  ├── no  → complete at header boundary
  └── yes → wait for header + body
```

This is the stream-framing layer used before `http_request::open()` parses the actual request.

### HTTP/2

`http2_protocol::read_stream()` recognizes the HTTP/2 connection preface and then validates the first frame as SETTINGS. Subsequent input is framed using the HTTP/2 frame header's 24-bit payload length.

The resulting frame data is consumed by `http2_session`, which maintains per-stream header state and the HPACK dynamic table.

```text
HTTP/2 connection preface
        ↓
SETTINGS
        ↓
HTTP/2 frames
        ↓
http2_session
   ├── stream id / flags
   ├── partial headers
   └── HPACK dynamic table
        ↓
http_request
```

### HTTP/2 frame layer

The `http2_frame` hierarchy represents protocol frames such as DATA, HEADERS, CONTINUATION, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE, PUSH_PROMISE, PRIORITY, and ALTSVC.

Frame encoding/decoding is separate from HPACK field compression:

```text
HTTP/2
 ├── frame layer      → sdk/net/http/http2
 └── header encoding  → sdk/net/http/hpack
                         ↓
                 common compression
```

### HTTP/3 boundary

The source tree contains HTTP/3 frame and QPACK components, but the parent HTTP README records QUIC and the HTTP/3 simple server as incomplete. The transport-side QUIC implementation lives under `sdk/net/tls/quic`.

Therefore this directory should not be read as a claim that HTTP/3 is a complete end-to-end server implementation.

## 3. Behavior Model

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Relationships



- `sdk/net/http/http_protocol.hpp/.cpp`
- `sdk/net/http/http2/http2_protocol.hpp/.cpp`
- `sdk/net/http/http2/http2_frame*.*`
- `sdk/net/http/http2/http2_session.*`
- `test/testcase/net/http/testcase_http.cpp`
- `test/testcase/net/http/testcase_http2_frame.cpp`
- `test/testcase/net/http/testvector_http2.cpp`
- [HTTP overview](README.md)
- [HTTP core model](http-core-model.md)
- [HTTP server/client flow](http-server-client.md)
- [HTTP/1.x implementation](http1/README.md)
- [HTTP/2 implementation](http2/README.md)
- [HTTP/3 implementation](http3/README.md)
- [TLS/QUIC transport](../tls/README.md)
- `../http-core-model.md` — shared HTTP request/response objects
- `../http1/` — HTTP/1.x message framing
- `../http2/` — HTTP/2 frame/session handling
- `../../server/` — generic `network_stream` and `network_protocol_group` dispatch

## 5. References

No external references are currently listed.