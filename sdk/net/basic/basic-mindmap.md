## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Basic socket mindmap

## 1. Role

This document identifies the module or protocol area represented by this file.

## 2. Model

```mermaid
mindmap
  root((basic))
    basic_socket
      client_socket
        naive_tcp_client_socket
        naive_udp_client_socket
        openssl_tls_client_socket
        openssl_dtls_client_socket
        client_socket_prosumer
          secure_client_socket
            trial_tls_client_socket
            trial_dtls_client_socket
          trial_tcp_client_socket
          trial_udp_client_socket
      server_socket
        naive_tcp_server_socket
          openssl_tls_server_socket
          trial_tls_server_socket
        naive_udp_server_socket
          openssl_dtls_server_socket
    server_socket_adapter
      openssl_server_socket_adapter
      trial_server_socket_adapter
    openssl_tls
    openssl_tls_context
    secure_prosumer
    tls_composer
    ipaddr_acl
```

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

See the referenced testcase sources for concrete examples. Where no direct test is identified, this is not evidence of runtime verification.

## 5. Relationships

Related implementation areas and protocol boundaries are recorded here where identified.

## 6. References

Source references and related documents are retained here where available.
