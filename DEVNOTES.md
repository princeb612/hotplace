## Notes

![hotplace](hotplace.png)

### Status

- in progress
  - ASN.1 (reboot)
- holding
  - QUIC
  - HTTP/3

### Map

```text
Legend: --> implemented    ..> not implemented yet

basic
  --> unittest
  |     --> test_case
  |     --> logger
  `--> pattern
        --> KMP
        --> trie
        --> suffixtree
        --> ukkonen
        `--> Aho-Corasick
                `--> +wildcard, +reducer

io
  --> CBOR
  ..> ASN.1

crypto
  --> JOSE
  |     --> JWS
  |     --> JWA
  |     --> JWE
  |     `--> JWK
  `--> COSE <-- CBOR
        --> key
        --> encrypt
        --> sign
        --> mac
        ..> hash

network
  --> multiplexer
  |     --> epoll
  |     --> IOCP
  `     ..> kqueue
  `--> transport
        --> TLS.openssl
        --> DTLS.openssl
        --> TLS.trial
        `--> DTLS.trial

epoll, IOCP, kqueue, TLS.openssl, DTLS.openssl,
TLS.trial, DTLS.trial
  --> network server
        --> HTTP/1.1
        --> HTTP/2
        |     `--> HPACK
        ..> HTTP/3
              ..> QUIC
                    `..> QPACK

HTTP/1.1, HPACK --> http_server
QPACK ..> http_server
```
