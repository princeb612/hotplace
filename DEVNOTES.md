
### Plan

#### io
```mermaid
flowchart LR
  A[io] --> B;
  B[CBOR];
  A-.-> C;
  C[asn1];
```

- holding
  - asn1

#### crypto
```mermaid
flowchart LR
  A[crypto] --> B;
  B[JOSE];
  A --> C1;
  C1[CBOR] --> C;
  C[COSE];
```

#### net
```mermaid
flowchart LR
  A[network] --> A1;
  A1[epoll] --> B;
  A --> A2;
  A2[IOCP] --> B;
  A --> A3;
  A3[TLS] --> B;
  A --> A4;
  A4[DTLS] --> B;
  A -.-> A5;
  A5[QUIC] -.-> B;
  B[network server] --> C;
  C[HPACK] --> D;
  D[HTTP/2];
  B --> E;
  E[QPACK] -.-> F;
  F[QUIC] -.-> G;
  G[HTTP/3];
```

- TODO
  - QUIC, HTTP/3

#### 

## Notes

### openssl

- execution failure cause of DLL binding
; after updating MINGW (pacman -Suy), application do not run

| API                   | minimum version |
| --                    | --              |
| BIO_err_is_non_fatal  | openssl 3.2~    |
| OPENSSL_LH_set_thunks | openssl 3.3~    |

- feature

| feature | API                   | minimum version |
| --      | --                    | --              |
| QUIC    | SSL_new_stream        | openssl 3.2~    |

