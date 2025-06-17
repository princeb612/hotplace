### HTTP

```mermaid
mindmap
  root((http))
    http_server
    http_server_builder
    http_uri
    http_header
    network_protocol
      http_protocol
      http2_protocol
    http_request
    http_response
    http_router
      html_documents
      http_authentication_provider
        basic_authentication_provider
        digest_access_authentication_provider
        bearer_authentication_provider
      http_authentication_resolver
        basic_credentials
        digest_credentials
        bearer_credentials
        oauth2_credentials
        custom_credentials
      oauth2_provider
        oauth2_grant_provider
          oauth2_authorization_code_grant_provider
          oauth2_implicit_grant_provider
          oauth2_resource_owner_password_credentials_grant_provider
          oauth2_client_credentials_grant_provider
```

- [x] HTTP/1.1
  - [x] Basic and Digest Access Authentication
  - [x] HTTP/1.1 simple server
- [x] HTTP/2
  - [x] HPACK
  - [x] HTTP/2 simple server
    - [x] server push
- [ ] HTTP/3
  - [x] QPACK
  - [ ] QUIC
  - [ ] HTTP/3 simple server

### HTTP/1.0
  - one request per connection
  - problem of RTT (packet round-trip time)
    - HTTP/1.1 Persistent Connection

### HTTP/1.1
  - Persistent Connection
    - keep-alive option
  - pipelining
    - client sends requests sequentially wo waiting for a response to the previous request
    - server responds in the order in which the requests were received
  - problem of TCP HOLB (Head of Line Blocking)
    - if the response to the previous request is delayed, all subsequent requests are blocked and the response is delayed
    - HTTP/2.0 SPDY, HTTP/3.0 QUIC

### HTTP/2.0
  - Multiplexed streams
    - SPDY (TCP-based)
    - problem of HOLB still exists
  - Head Compression
  - Server Push

### HTTP/3.0
  - QUIC (UDP-based)

### comments

| compression      |                       | compression                        |               |
| --               | --                    | --                                 | --            |
| deflate          | TLS-level compression | LZ77 + Huffman coding              | CRIME attack  |
| gzip             | content-encoding      | LZ77 + Huffman coding              | BREACH attack |
| deflate          | content-encoding      | LZ77 + Huffman coding              | BREACH attack |
| br               | content-encoding      | LZ77 + Huffman + Context Modeling  | BREACH attack |
| zstd             | content-encoding      | LZ77 + Finite State Entropy        |               |
| identity         | content-encoding      | N/A                                |               |
