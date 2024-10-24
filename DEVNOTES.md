## Notes

- [Plan](#plan)
- [Memo](#memo)
- [TODO](#todo)

### Plan

#### basic
```mermaid
flowchart LR
  A[basic];
  B[unittest];
  C[pattern];
  A --> B;
  A --> C;
  B --> B1[test_case];
  B --> B2[logger];
  C --> C1[KMP];
  C --> C2[trie];
  C --> C3[suffixtree];
  C --> C4[ukkonen];
  C --> C5[Aho-Corasick];
  C5 --> C6[+wildcard];
```

#### io
```mermaid
flowchart LR
  A --> B;
  A -.-> C;
  A[io];
  B[CBOR];
  C[ASN.1];
```

- holding
  - asn1

#### crypto
```mermaid
flowchart LR
  A[crypto];
  B[JOSE];
  C1[CBOR];
  C2[COSE];
  A --> B;
  A --> C1;
  C1 --> C2;
```

#### net
```mermaid
flowchart LR
  A[network] --> A1[epoll];
  A --> A2[IOCP];
  A --> A3[TLS];
  A --> A4[DTLS];
  A -.-> A5[QUIC];
  A1 --> B;
  A2 --> B;
  A3 --> B;
  A4 --> B;
  A5 -.-> B;
  B[network server];
  B --> C1[http_server];
  C1 --> C2[HTTP/1.1];
  B --> D1[HPACK];
  D1 --> D2[HTTP/2];
  B --> E1[QPACK];
  E1 -.-> E2[HTTP/3];
```

- TODO
  - QUIC, HTTP/3

## Memo

### openssl

- execution failure cause of DLL binding error
; after updating MINGW (pacman -Suy), test application do not work

| API                   | minimum version |
| --                    | --              |
| BIO_err_is_non_fatal  | openssl 3.2~    |
| OPENSSL_LH_set_thunks | openssl 3.3~    |

- feature

| feature | API                   | minimum version |
| --      | --                    | --              |
| QUIC    | SSL_new_stream        | openssl 3.2~    |
| KDF     | OSSL_set_max_threads  | openssl 3.2~    |

## TODO

- [ ] HTTP/3
- [ ] QUIC
- [x] QPACK
  - [x] encoder
  - [x] static table
  - [x] dynamic table
- [x] HPACK
  - [x] huffman coding
  - [x] encoder
  - [x] static table
  - [x] dynamic table
- [x] UDP/DTLS
  - [x] integration - multiplexer (epoll, IOCP)
  - [x] integration - network_server
- [x] HTTP/2
  - [x] integration - http_server
  - [x] Server Push
- [x] HTTP/1.1
  - [x] integration - http_server
  - [x] Basic Authentication
  - [x] Digest Access Authentication
  - [x] Bearer Authentication
  - [x] OAuth2
- [x] pattern
  - [x] KMP
  - [x] trie
  - [x] suffixtree
  - [x] ukkonen
  - [x] Aho-Corasick
    - [x] wildcard (single ?, any *)
- [x] graph
  - [x] DFS
  - [x] BFS
  - [x] Dijkstra
- [x] COSE
  - [x] CBOR
  - [x] CWK
    - [x] HMAC
    - [x] RSA
    - [x] EC
    - [x] OKP
  - [x] encrypt
  - [x] sign
  - [x] mac
  - [ ] hash
- [x] JOSE
  - [x] JWK
    - [x] HMAC
    - [x] RSA
    - [x] EC
    - [x] OKP
  - [x] JWA
  - [x] JWE
  - [x] JWS
- [ ] ASN.1

sub-tasks

- [ ] shutdown DTLS peer connection
- [ ] br(Brotli), zstd(Zstandard) HTTP encoding
