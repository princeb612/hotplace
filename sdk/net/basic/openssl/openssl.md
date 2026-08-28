## OpenSSL - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: An OpenSSL library-based TLS/DTLS encrypted session management, SSL Context wrapping, and secure client/server socket implementation module.
* **Key Features**:
  * **SSL/TLS Context Management**: Handles `SSL_CTX` creation, certificate/private key loading, and SSL option management operations (`openssl_tls_context.cpp`, `openssl_tls_context_sdk.cpp`).
  * **TLS & DTLS Socket Abstraction**: OpenSSL-based TLS/DTLS client and server socket handling operations (`openssl_tls_client_socket.cpp`, `openssl_tls_server_socket.cpp`, `openssl_dtls_client_socket.cpp`, `openssl_dtls_server_socket.cpp`).
  * **Server Socket Adapter**: Binds OpenSSL server socket instances to existing network loops (`openssl_server_socket_adapter.cpp`).
  * **OpenSSL Engine Abstraction & SDK**: Wraps common OpenSSL pipelines and interfaces (`openssl_tls.cpp`, `sdk.cpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **SSL Context & Engine Management (`openssl_tls_context.cpp`, `openssl_tls.cpp`)**:
  * Manages `SSL_CTX` lifecycles, loads CA certificates for verification, and handles C++11 wrapper objects.
* **TLS Socket Operations (`openssl_tls_client_socket.cpp`, `openssl_tls_server_socket.cpp`)**:
  * Handles non-blocking TLS handshakes and asynchronous read/write operations based on `SSL_connect` and `SSL_accept`.
* **DTLS Socket Implementation (`openssl_dtls_client_socket.cpp`, `openssl_dtls_server_socket.cpp`)**:
  * Wraps UDP-based Datagram TLS (DTLS) sessions and processes handshake operations.
* **Server Adapter Integration (`openssl_server_socket_adapter.cpp`)**:
  * Automatically binds OpenSSL SSL sessions upon receiving asynchronous server socket connections.

---

### 3. Core Operating Mechanism

* **OpenSSL Handshake & Session Flow (`openssl_tls_context.cpp`, `openssl_tls_client_socket.cpp`)**:
  * Creates `openssl_tls_context` and loads certificates/keys -> Binds client/server sockets (`openssl_tls_client_socket` / `openssl_tls_server_socket`) -> Calls `SSL_do_handshake` and completes handshake -> Executes encrypted stream read/write operations.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-OSSL-01** | Supplement retry handling for non-blocking `SSL_ERROR_WANT_READ` / `SSL_ERROR_WANT_WRITE` in `openssl_tls_client_socket.cpp`<br> | High | Open |
| **TODO-OSSL-02** | Verify exception handling for certificate loading failures and null pointers from `SSL_CTX_new` in `openssl_tls_context.cpp`<br> | High | Open |
| **TODO-OSSL-03** | Verify DTLS Cookie Exchange and replay attack prevention logic in `openssl_dtls_server_socket.cpp`<br> | High | Open |
| **TODO-OSSL-04** | Check for memory leaks during `SSL_free` / `SSL_shutdown` upon asynchronous session termination in `openssl_server_socket_adapter.cpp`<br> | Medium | Open |
| **TODO-OSSL-05** | Verify ALPN (Application-Layer Protocol Negotiation) protocol selection operations in `openssl_tls.cpp`<br> | Low | Open |
