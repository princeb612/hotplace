# HTTP core model

## Role

`sdk/net/http` contains the common HTTP model used by the HTTP/1.x and HTTP/2 implementations, together with the server/client, routing, URI, header, and authentication layers.

The central objects are:

```text
http_server / http_client
        │
        ├── http_request
        ├── http_response
        └── http_router
              │
              └── authentication / resource handling

http_request / http_response
        │
        ├── http_header
        └── http_uri
```

`http_request` and `http_response` are deliberately shared by HTTP/1.x and HTTP/2. HTTP/2 additionally carries a stream id and HPACK dynamic-table state.

## Request and response

`http_request` can parse an incoming HTTP/1.x request, compose a request, expose its method/URI/header/content, and carry HTTP version and stream information. It has separate HTTP/1 and HTTP/2 parsing paths.

`http_response` represents the server response and can compose either an HTTP/1.x byte stream or an HTTP/2 response representation. `respond(network_session*)` is the boundary where the response is sent through the active network session.

## Header and URI

`http_header` is the common header container. It also provides conversion of structured authentication header values into `skey_value`, which is used by the authentication layer.

`http_uri` separates the original URI, path, and query string and can expose query parameters through `skey_value`.

## Routing

`http_router` maps URI paths and status codes to handlers. The routing path is approximately:

```text
network/session
    ↓
http request
    ↓
http_router::route()
    ├── authentication provider / resolver
    ├── URI handler
    ├── html_documents
    └── 404/status handler
    ↓
http_response
```

Authentication is therefore part of request dispatch rather than a separate transport layer.

## Compression and content encoding

HTTP content encoding (`identity`, `deflate`, `gzip`, etc.) is handled while composing responses. This is different from HTTP/2 HPACK and HTTP/3 QPACK, which compress header fields rather than response bodies.

## Source / tests

Primary source:

- `sdk/net/http/http_request.*`
- `sdk/net/http/http_response.*`
- `sdk/net/http/http_header.*`
- `sdk/net/http/http_uri.*`
- `sdk/net/http/http_router.*`

Direct tests:

- `test/testcase/net/http/testcase_http.cpp`

Related records:

- [HTTP server/client flow](http-server-client.md)
- [HTTP protocol stack](http-protocol-stack.md)
- [Authentication](auth/README.md)
- [Compression infrastructure](compression/README.md)
