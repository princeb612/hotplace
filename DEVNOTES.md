
## Notes

- [Release](#release)
- [Plan](#plan)
- [Memo](#memo)
- [TODO](#todo)

### Release

TLS
- RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 8448 Example Handshake Traces for TLS 1.3
  - TLS over TCP not yet

DTLS
- RFC 9147 The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
  - DTLS over UDP not yet

QUIC
- RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001 Using TLS to Secure QUIC
- RFC 9369 QUIC Version 2

HTTP/1.1, HTTP/2
- RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
- RFC 7616 HTTP Digest Access Authentication
- RFC 6749 The OAuth 2.0 Authorization Framework
- RFC 7541 HPACK: Header Compression for HTTP/2
- RFC 7540 Hypertext Transfer Protocol Version 2 (HTTP/2)
  - basic request/response
  - not support authentication schemes yet

JOSE
- RFC 7515 JSON Web Signature (JWS)
- RFC 7516 JSON Web Encryption (JWE)
- RFC 7517 JSON Web Key (JWK)
- RFC 7518 JSON Web Algorithms (JWA)
- RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
- RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)

COSE
- RFC 7049 Concise Binary Object Representation (CBOR)
- RFC 8152 CBOR Object Signing and Encryption (COSE)
- RFC 8230 Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages
- RFC 8392 CBOR Web Token (CWT)
- RFC 8812 CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms
- RFC 8949 Concise Binary Object Representation (CBOR)
- RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 9053 CBOR Object Signing and Encryption (COSE): Initial Algorithms
- RFC 9338 CBOR Object Signing and Encryption (COSE): Countersignatures

### Plan

- in progress
  - TLS
  - QUIC
  - HTTP/3
- holding
  - asn1
- flowchart
  - line : implemented
  - dot-line : not implemented yet

```mermaid
flowchart LR
  A[basic];

  AA[unittest];
  AB[pattern];
  A --> AA;
  A --> AB;

  AA1[test_case];
  AA2[logger];
  AB1[KMP];
  AB2[trie];
  AB3[suffixtree];
  AB4[ukkonen];
  AB5[Aho-Corasick];
  AB51[+wildcard];
  AA --> AA1;
  AA --> AA2;
  AB --> AB1;
  AB --> AB2;
  AB --> AB3;
  AB --> AB4;
  AB --> AB5;
  AB5 --> AB51;

  B[io];

  BA[CBOR];
  BB[ASN.1];
  B --> BA;
  B -.-> BB;

  C[crypto];

  CA[JOSE];
  CB[COSE];
  C --> CA;
  C ---> CB;
  BA --> CB;

  CA1[JWS];
  CA2[JWA];
  CA3[JWE];
  CA4[JWK];
  CA --> CA1;
  CA --> CA2;
  CA --> CA3;
  CA --> CA4;

  CB1[key];
  CB2[encrypt];
  CB3[sign];
  CB4[mac];
  CB5[hash];
  CB --> CB1;
  CB --> CB2;
  CB --> CB3;
  CB --> CB4;
  CB -.-> CB5;

  D[network];

  DA[multiplexer];
  DB[transport];
  D --> DA;
  D --> DB;

  DA1[epoll];
  DA2[IOCP];
  DA3[kqueue];
  DA --> DA1;
  DA --> DA2;
  DA -.-> DA3;

  DB1[TLS.openssl];
  DB2[DTLS.openssl];
  DB3[QUIC.implement];
  DB4[TLS.implement];
  DB5[DTLS.implement];
  DB --> DB1;
  DB --> DB2;
  DB -.-> DB3;
  DB -.-> DB4;
  DB -.-> DB5;
  DA1 --> DC;
  DA2 --> DC;
  DA3 -.-> DC;
  DB1 --> DC;
  DB2 --> DC;
  DB3 -.-> DC;
  DB4 -.-> DC;
  DB5 -.-> DC;

  DC[network server];
  DC1[HTTP/1.1];
  DC2[HPACK];
  DC3[HTTP/2];
  DC4[QPACK];
  DC5[HTTP/3];

  DC --> DC1;
  DC --> DC2;
  DC2 --> DC3;
  DC --> DC4;
  DC4 -.-> DC5;

  DD[http_server];
  DC1 --> DD;
  DC3 --> DD;
  DC5 -.-> DD;
```

## Memo

### openssl

- execution failure cause of DLL binding error
; after updating MINGW (pacman -Suy), test application do not work

| API                    | version      |
| --                     | --           |
| BIO_err_is_non_fatal   | openssl 3.2~ |
| OPENSSL_LH_set_thunks  | openssl 3.3~ |
| EVP_MD_CTX_get_size_ex | openssl 3.4~ |

- feature

| feature | API                   | minimum version |
| --      | --                    | --              |
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
- [ ] TLS (understanding record, handshake, extension)
  - [x] tls13.xargs.org
  - [x] tls12.xargs.org
  - [x] dtls.xargs.org
  - [x] RFC 8448
    - [x] 1-RTT
    - [x] 0-RTT
    - [x] HelloRetryRequest
    - [x] Client Authentication
    - [x] compatibility mode
  - [x] verify
    - [x] pre shared key (psk binder)
    - [x] certificate verify
    - [x] finished
  - [x] TLS construct
    - [x] TLS version
      - [x] TLS1.3
      - [x] TLS1.2
  - [ ] DTLS construct
    - [x] TLS version
      - [x] TLS1.3
      - [ ] TLS1.2
  - [ ] TLS over TCP
  - [ ] DTLS over UDP

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

- [ ] COSE partial iv
- [ ] shutdown DTLS peer connection
- [ ] br(Brotli), zstd(Zstandard) HTTP encoding
- [ ] HTTP/2 Authentication Scheme

## summary

```mermaid
journey
  title 2025
  section 2025.01
    TLS:3:github
  section 2025.02
    TLS, QUIC:3:github
    Zelda TOTK 100%/100%:5:game
  section 2025.03
    Zelda BOTW Master Mode:5:game
    Monster Hunter Wilds:7:game
```

```mermaid
journey
  title 2024
  section 2024.01
    HTTP/1.1, authentication:3:github
  section 2024.02
    hospital:0:refresh
  section 2024.03
    HTTP/1.1, oauth2:3:github
  section 2024.04
    HPACK, HTTP/2:3:github
  section 2024.05
    HTTP/2:3:github
  section 2024.06
    ASN.1, graph:3:github
  section 2024.07
    pattern search:3:github
  section 2024.08
    pattern search:3:github
  section 2024.09
    review:3:github
  section 2024.10
    QPACK:3:github
  section 2024.11
    QUIC:3:github
  section 2024.12
    TLS:3:github
```

```mermaid
journey
  title 2023
  section 2023.07~08
    Zelda BOTW, TOTK:5:game
  section 2023.09
    CBOR:3:github
  section 2023.10~12
    COSE:3:github
```
