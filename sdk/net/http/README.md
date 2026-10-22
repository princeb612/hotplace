## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HTTP

## 1. Role

`sdk/net/http` contains the common HTTP request/response model, URI and header handling, server/client integration, routing, authentication helpers, version-specific protocol framing, and HPACK/QPACK header compression. The parent directory owns shared HTTP concepts; the subdirectories own version-specific wire formats and compression algorithms.

HTTP/1.x, HTTP/2, and HTTP/3 are not a single interchangeable path: HTTP/1.x uses textual message framing over TCP, HTTP/2 uses binary frames and streams, and HTTP/3 uses HTTP frames over QUIC streams.

The server applets provide concrete integration points for the first two paths: `test/applet/httpserver1` configures `http_server` for HTTP/1.1, while `test/applet/httpserver2` enables HTTP/2 on the same higher-level server abstraction. The change is in the HTTP protocol path selected and handled by the server, not a replacement of the shared socket/session layer. HTTP/3 classes in this directory should not be inferred to provide an equivalent complete server applet.

## 2. Data Model

```text
Application-facing layer
  http_server / http_server_builder / http_client
  http_router -> registered handler callback
       └─ optional authentication provider

Shared HTTP message model
  http_request
    ├─ method / body
    ├─ http_uri -> URI / path / query
    └─ http_header
  http_response
    ├─ status / body
    └─ http_header

Version-specific protocol paths
  HTTP/1.x -> http_protocol -> request/response framing
  HTTP/2   -> http2_protocol -> frames -> http2_session -> HPACK
  HTTP/3   -> HTTP/3 frames over QUIC streams -> QPACK
```

The common objects represent HTTP semantics; they do not replace the framing and session state needed by each protocol version. `http_header` also provides parsing support for structured authentication values, while `http_uri` owns URI decomposition and query parameters. Content encoding for a response body is separate from HPACK/QPACK header compression.

## 3. Behavior Model

### Server request path

```text
http_server_builder
  -> choose server_socket_adapter + configure options
  -> build http_server
  -> network_server opens sockets and event/session workers
  -> network_stream / network_protocol frames incoming bytes
  -> http_server::consume()
       ├─ HTTP/1.x -> http_request
       └─ HTTP/2   -> http2_session -> http_request
  -> http_router::route()
       ├─ optional authentication provider/resolver
       └─ registered URI handler callback
  -> http_response
  -> network_session send path
```

`network_server` owns the transport event and session lifecycle; `http_server` configures the HTTP protocols and turns completed protocol data into request/response work. The router selects application handlers, while the handler supplies the response. HTTP/3's QUIC/frame components are present in the source tree, but the HTTP/3 server path is incomplete; the presence of frame and QPACK classes should not be described as complete HTTP/3 service support.

### Subdirectory boundaries

- `auth/` — credentials and authentication-provider behavior.
- `compression/` — shared static/dynamic table abstractions and compression-stream support.
- `http1/` — HTTP/1.x framing adapter.
- `http2/` — HTTP/2 frame/protocol/session state.
- `http3/` — HTTP/3 frame representation above QUIC streams.
- `hpack/` — HTTP/2 header compression.
- `qpack/` — HTTP/3 field compression.

## 4. Relationships

- [HTTP core model](http-core-model.md) — request, response, URI, header, routing, and authentication relationships.
- [HTTP server/client flow](http-server-client.md) — builder options, startup, protocol registration, handler callback and client path.
- [HTTP protocol stack](http-protocol-stack.md) — the network stream/protocol framing boundary.
- [Authentication](auth/README.md)
- [Header compression infrastructure](compression/README.md)
- [HTTP/1.x](http1/README.md), [HTTP/2](http2/README.md), [HTTP/3](http3/README.md)
- [HPACK](hpack/README.md), [QPACK](qpack/README.md)
- [Network server](../server/README.md) — multiplexer, session, stream and protocol dispatch.
- [Basic socket layer](../basic/README.md) and [TLS/DTLS/QUIC](../tls/README.md) — transport and secure-session integration.
- [HTTP testcase documentation](../../../test/testcase/net/http/README.md), [HPACK tests](../../../test/testcase/net/hpack/README.md), and [QPACK tests](../../../test/testcase/net/qpack/README.md) — source-level testcase inventory and evidence.

## 5. References

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112)
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 7541 — HPACK](https://www.rfc-editor.org/rfc/rfc7541)
- [RFC 9204 — QPACK](https://www.rfc-editor.org/rfc/rfc9204)

## 6. Developer Notes

### Protocol evolution notes

These notes preserve the original developer-oriented comparison; they are conceptual background, not a claim that every item is implemented by this repository.

- **HTTP/1.0:** commonly one request per connection; repeated connection setup adds round trips.
- **HTTP/1.1:** persistent connections reduce connection setup overhead. Pipelining preserves response order and can still cause application-level head-of-line blocking when an earlier response is delayed.
- **HTTP/2:** multiplexes streams over one TCP connection and compresses header fields with HPACK. TCP loss can still block delivery for all streams sharing that connection.
- **HTTP/3:** maps HTTP semantics to QUIC streams over UDP and uses QPACK. QUIC changes transport-level loss/multiplexing behavior; it is not simply HTTP/2 frames moved to UDP.

### Compression terminology note

Body content encodings such as gzip/deflate and header compression such as HPACK/QPACK are separate mechanisms. Historical notes in this area mention TLS compression and CRIME/BREACH; do not read that legacy table as a recommendation to enable TLS compression. TLS-level compression is not the normal modern HTTPS configuration, and response-body compression risks depend on whether attacker-controlled and secret data share a compressed context.
