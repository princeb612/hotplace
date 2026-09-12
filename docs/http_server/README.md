# HTTP Server

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1078            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```

## Context

The HTTP server layer connects the generic `network_server` infrastructure with HTTP protocol processing and the application callback.

It is therefore more useful to understand `http_server` as an orchestration layer than as an HTTP parser. Network events are converted into protocol-aware requests, routed through authentication and URI handling, and finally delivered to the application.

The current implementation provides an HTTP/1.1 and HTTP/2 server path, with TLS integration and an HTTP/3/QUIC configuration path present in the builder.

## History

The current server architecture follows the earlier `network_server` development.

Relevant milestones recorded in `CHANGELOG.md` include:

- Revision 777 — server socket and `netserver` integration tested.
- Revision 794 — HTTP/1.1 server tested in the MINGW64 environment.
- Revision 795 — HTTP/2 server tested in the MINGW64 environment.
- Revision 799 — HTTP/1.1 `http_server` tested in a Linux environment.
- Revision 803 — HTTP/1.1 interoperability tested with curl.
- Revision 804 — HTTP/2 interoperability tested with curl.
- Revision 617 — DTLS support added to `network_server`.
- Revision 601 — UDP support added to `network_server`.

This history explains the layering: transport/session processing was established first, then HTTP became an application-level consumer of the same network infrastructure.

## Conceptual

### Server role

The server can be viewed as four layers:

```text
Application
    │
    │ http_request / http_response
    ▼
HTTP server
    │
    ├── HTTP/1.1 protocol
    ├── HTTP/2 protocol
    └── HTTP/3 configuration path
    │
    ▼
network_server
    │
    ├── network_session
    ├── network_stream
    ├── multiplexer
    └── socket / transport
```

For HTTPS, TLS is inserted below HTTP protocol handling:

```text
HTTP application
      │
 HTTP request/response
      │
 HTTP/1.1 or HTTP/2
      │
     TLS
      │
     TCP
```

HTTP/3 follows a different transport model:

```text
HTTP application
      │
    HTTP/3
      │
     QUIC
      │
     UDP
```

### Event → session → message

The important boundary is not simply "one socket read = one HTTP message".

```text
network event
     │
     ▼
network_session
     │
     ▼
network_stream / datagram
     │
     ▼
protocol detection and consumption
     │
     ▼
complete HTTP message
     │
     ▼
http_request
     │
     ▼
application
```

A TCP stream can contain:

```text
read #1
  ├── partial request
  └── incomplete remainder

read #2
  ├── completes request A
  └── begins request B

read #3
  └── completes request B
```

Consequently, stream boundaries are not HTTP message boundaries.

UDP provides datagram boundaries, but the protocol above UDP may still have its own reconstruction rules. DTLS is an example.

## Structural

### `http_server`

The central object owns the integration points:

```text
http_server
├── network_server
├── server_conf
├── HTTP configuration
├── server_socket_adapter
├── IP address ACL
├── HTTP/1.1 protocol
├── HTTP/2 protocol
├── HTTP router
└── application consumer
```

`start()` starts the configured network consumer/event processing. `stop()` breaks those loops.

`startup_server()` creates the endpoint according to the requested service:

```text
service_http   → TCP
service_https  → TLS over TCP
service_http3  → QUIC
```

The server then registers the HTTP protocol handlers with the underlying network server.

### Protocol selection

When an incoming network event reaches `http_server::consume()`:

```text
network event
     │
     ├── mux_read / mux_dgram
     │
     ▼
HTTP/1.1 detection
     │
     ├── yes ──► http_request::open()
     │
     └── no
          │
          ▼
       HTTP/2 path
          │
          └──► http2_session::consume()
                    │
                    ▼
               http_request
```

The application callback is invoked only after a request object has been produced.

This keeps network event processing separate from application routing.

### Builder

`http_server_builder` is the configuration boundary.

```text
http_server_builder
       │
       ├── IPv4 / IPv6
       ├── HTTP / HTTPS
       ├── HTTP/1.1
       ├── HTTP/2
       ├── HTTP/3
       ├── TLS certificate
       ├── TLS cipher list
       ├── peer verification
       ├── content encoding
       └── application handler
       │
       ▼
    http_server
```

The builder opens the requested endpoints and selects ALPN according to the enabled HTTP version:

```text
HTTP/3 enabled → h3
otherwise
HTTP/2 enabled → h2
otherwise
HTTP/1.1       → http/1.1
```

The HTTP/3 path is present in the builder through the QUIC service, but it should not be interpreted as proof that the complete HTTP/3 server integration is finished.

### Router as the application boundary

`http_router` converts an HTTP request into an application response.

```text
http_request
     │
     ▼
authentication lookup
     │
     ├── authentication required
     │       │
     │       └── resolver
     │             ├── success → continue
     │             └── failure → request authentication
     │
     ▼
URI handler lookup
     │
     ├── explicit handler
     │
     ├── HTML document
     │
     └── 404 handler
     │
     ▼
http_response
```

The router owns three important mappings:

```text
URI
 └──► request handler

status code
 └──► status handler

URI
 └──► authentication provider
```

Static HTML handling is a fallback after an explicit URI handler is not found. HTTP/2 server push can also be triggered from the document-serving path when the session and server-push configuration permit it.

The router is therefore the point where protocol-level request handling crosses into application semantics.

### Resource and protocol data

`http_resource` is not the application resource server. It provides protocol-oriented names and predefined data such as HTTP status text, methods, HTTP/2 frame information, HTTP/3 frame information, and HPACK/QPACK static tables.

Application documents are handled through `html_documents` and the router.

## Flow

### HTTP/1.1 over HTTPS

```text
Browser / curl
     │
     │ TCP + TLS
     ▼
server socket
     │
     ▼
network_server
     │
     ▼
network_session / network_stream
     │
     ▼
TLS processing
     │
     ▼
HTTP/1.1 detection
     │
     ▼
http_request
     │
     ▼
http_router
     │
     ├── authentication
     ├── URI handler
     ├── HTML document
     └── 404
     │
     ▼
http_response
     │
     ▼
network_session
     │
     ▼
TLS + TCP
```

### HTTP/2 over HTTPS

```text
Browser / curl
     │
     │ TCP + TLS
     │ ALPN: h2
     ▼
network_server
     │
     ▼
network_session
     │
     ▼
HTTP/2 session
     │
     ├── frame processing
     ├── HPACK
     └── stream processing
     │
     ▼
http_request
     │
     ▼
http_router
     │
     ▼
http_response
```

The HTTP/2 testcase can exercise this path without a live socket by feeding encoded frames through a `network_session` stream and then passing the resulting content into `http2_session`.

### Multiple messages in one read

```text
TCP read
┌─────────────────────────────────────┐
│ HTTP message A │ HTTP message B ... │
└─────────────────────────────────────┘
        │
        ▼
network_stream
        │
        ├── consume A
        │
        └── preserve remainder
                 │
                 ▼
             consume B
```

The stream abstraction must therefore preserve unconsumed bytes. A stream is not a ring buffer merely because it accumulates chunks: queued input is assembled into the stream representation, protocol detection determines how much constitutes a complete message, and only the consumed range is removed.

### Partial message

```text
read A
  │
  └── incomplete HTTP message
          │
          ▼
     retain stream data

read B
  │
  └── remaining bytes
          │
          ▼
     complete message
          │
          ▼
      http_request
```

This is one reason the generic `network_stream` layer belongs below HTTP.

## Study & Verification

### HTTP data model

`test/testcase/net/http/testcase_http.cpp` covers:

- URI parsing and escaping
- request construction
- response composition and parsing
- form-encoded body parameters
- Basic authentication
- Digest authentication
- RFC 2617 digest examples
- HTML documents
- HTTP client/TLS client usage
- bearer authentication

These tests verify the HTTP objects independently of the live server.

### HTTP/2 frame verification

`testcase_http2_frame.cpp` performs frame round-trip checks:

```text
compose frame
     │
     ▼
compare expected binary
     │
     ▼
read binary
     │
     ▼
write frame
     │
     ▼
compare again
```

The tested frame families include SETTINGS, HEADERS, CONTINUATION, DATA, GOAWAY, and ALTSVC.

### HTTP/2 capture/test-vector path

`testvector_http2.cpp` feeds HTTP/2 frame examples into a `network_session` stream and then into `http2_session`.

This is useful because it verifies the relationship between:

```text
wire-format frame
      ↓
network session/stream
      ↓
HTTP/2 session
      ↓
HTTP request
```

without requiring a live browser connection.

### Live server interoperability

`test/applet/httpserver1` exercises the HTTP/1.1 server with:

- `network_server`
- libssl
- trial TLS mode
- Chrome/Edge
- curl
- OpenSSL `s_client`
- TLS 1.3
- TLS 1.2
- SSLKEYLOGFILE
- ML-KEM key exchange groups
- ML-DSA certificates

The HTTP/2 applet, `test/applet/httpserver2`, exercises:

- `network_server`
- HTTP/2
- libssl
- trial mode
- ALPN
- browser/curl interoperability

The server examples are therefore integration tests as well as usage examples.

### Traffic captures

PCAPNG files should be treated as development and verification artifacts rather than as the HTTP implementation itself.

The broader workflow is:

```text
implementation
     │
     ▼
traffic generation
     │
     ├── trial server
     ├── curl
     ├── openssl s_client
     └── browser
     │
     ▼
PCAPNG + SSLKEYLOG + debug trace
     │
     ├── protocol/interoperability analysis
     │
     └── selected captures converted to
         replayable test vectors
```

This makes packet captures part of the development feedback loop: they can expose interoperability problems, correlate encrypted traffic with key logs, and later become regression material through capture replay.

## Status

As of Revision 1078 / Release 1.137:

- HTTP/1.1 server path — implemented and tested.
- HTTP/2 server path — implemented and tested.
- TLS integration — used by the HTTPS server examples.
- HTTP authentication — implemented through router/provider integration.
- Static HTML document fallback — implemented.
- HTTP/2 server push — integrated into the router/document path.
- HTTP/2 frame and test-vector verification — present.
- HTTP/1.1 and HTTP/2 browser/curl interoperability — documented and exercised.
- Trial-mode server verification — present.
- HTTP/3/QUIC configuration path — present in the builder, but the complete HTTP/3 server integration should remain considered incomplete.

The important architectural result is the separation:

```text
network_server
     │
     ▼
transport/session/stream
     │
     ▼
HTTP protocol
     │
     ▼
http_request
     │
     ▼
http_router
     │
     ▼
application handler
```

That separation allows the HTTP layer to reuse the same network/session machinery rather than implementing a second independent server architecture.
