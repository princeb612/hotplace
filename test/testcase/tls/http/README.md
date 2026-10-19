#### HTTP

- [sslkeylog](sslkeylog)
- http1.pcapng
  - [google chrome](https://[::1]:9000)
  - [httpserver1](http1.md)
- http2.pcapng
  - [google chrome](https://127.0.0.1:9000)
  - [httpserver2](http2.md)
- http2_trial.pcap2
  - [google chrome](https://127.0.0.1:9000)
  - [httpserver2](http2_trial.md)
- curl_http1_tls12.pcapng
  - [curl](curl_http1_tls12.md)
- curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.pcapng
  - [curl](curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256-client.md)
  - [httpserver1](curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256-server.md)


## Protocol and capture distinctions

The directory pairs HTTP/1.1 and HTTP/2 traffic with TLS captures, and includes separate HTTP/2 paths for the `trial` implementation and the regular server applet. The `curl_http1_*` files document a client/server exchange under named TLS configurations.

These files are packet-level evidence for specific local runs. They should be read together with the linked trace notes and the HTTP server applet documentation, not as a standalone claim of complete browser interoperability.
