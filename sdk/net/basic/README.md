## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Basic network socket layer

## 1. Role

`basic` provides the low-level socket abstractions used by the higher network layers.

The directory separates the common socket interface from concrete transport/backend implementations:

- `basic_socket`, `client_socket`, `server_socket` — common socket abstractions and lifecycle
- `naive/` — direct TCP/UDP socket implementations
- `openssl/` — TLS/DTLS socket and OpenSSL context integration
- `trial/` — experimental composition layer for secure/QUIC-related socket flows
- `ipaddr/` — address ACL support

The original class relationship mindmap is preserved separately in [basic-mindmap.md](basic-mindmap.md).

## 2. Model

### Module records

- [socket model](socket-model.md) — common socket hierarchy, scheme and lifecycle
- [OpenSSL socket adapter](openssl-socket-adapter.md) — TLS/DTLS socket integration
- [trial socket composer](trial-socket-composer.md) — experimental composition layer
- [IP address ACL](ipaddr_acl.md) — address/range/CIDR access control

Existing implementation-specific notes remain under [naive/](naive/), [openssl/](openssl/), and [trial/](trial/).

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

### Related tests

- [network basic testcase](../../../test/testcase/net/basic/README.md)
- `test/testcase/net/basic/testcase_acl.cpp`

## 5. Relationships

### Related areas

- `sdk/net/server/` — server-side socket/session integration
- `sdk/net/tls/` — TLS/DTLS/QUIC integration

## 6. References

Source references and related documents are retained here where available.
