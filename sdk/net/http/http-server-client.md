# HTTP server and client flow

## Server

`http_server` is the application-facing integration point between `network_server` and the HTTP request/response model.

Startup selects a socket service and registers the corresponding protocol interpreters:

```text
http_server::startup_server()
        ↓
server_socket_adapter
        ↓
network_server::open()
        ↓
accept handler
        ↓
network_server protocol group
        ├── http_protocol
        └── http2_protocol (when enabled)
```

The consume callback receives network events and distinguishes HTTP/1.x from HTTP/2. HTTP/1.x is parsed directly into `http_request`; HTTP/2 frames are accumulated through the session's `http2_session` until a complete request is available.

```text
network event
    ↓
http_server::consume()
    ├── HTTP/1.x → http_request::open()
    └── HTTP/2   → http2_session::consume()
                         ↓
                    http_request
    ↓
application handler
    ↓
http_response
```

The server supports TCP, TLS, and the QUIC-facing service selection used by the HTTP/3 path, although the current HTTP/3 server path remains incomplete in the source's own status map.

## Client

`http_client` is intentionally simple. It creates/composes an `http_request`, connects through a client socket, sends the serialized request, reads the response, runs the received bytes through a `network_protocol_group` containing `http_protocol`, and opens the resulting bytes as an `http_response`.

```text
URL
 ↓
split_url
 ↓
http_request::compose()
 ↓
client_socket
 ↓ send
network stream
 ↓
http_protocol
 ↓
http_response::open()
```

The current implementation shown here is primarily the HTTP/1.x request/response path. HTTP/2 has its own frame/session machinery rather than being transparently selected by this simple client flow.

## Routing boundary

The server does not embed application handlers inside the protocol parser. `http_router` is the boundary between protocol parsing and application behavior:

```text
network_server
  ↓
protocol interpreter
  ↓
http_request
  ↓
http_router
  ↓
application handler
  ↓
http_response
```

This separation is important when reading the code: `http_protocol` determines whether enough bytes form a message, while the router determines what the message means to the application.

## Source / tests

- `sdk/net/http/http_server.*`
- `sdk/net/http/http_client.*`
- `sdk/net/http/http_router.*`
- `test/testcase/net/http/testcase_http.cpp`
- `test/applet/httpserver1/`
- `test/applet/httpserver2/`
