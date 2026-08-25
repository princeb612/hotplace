## OpenSSL module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: OpenSSL library 기반 TLS/DTLS 암호화 session 관리, SSL Context wrapping 및 보안 client/server socket 구현 module.
* **주요 기능**:
  * **SSL/TLS Context Management**: SSL_CTX 생성, 인증서/개인키 load 및 SSL option 관리 연산 (`openssl_tls_context.cpp`, `openssl_tls_context_sdk.cpp`).
  * **TLS & DTLS Socket Abstraction**: OpenSSL 기반 TLS/DTLS client 및 server socket handling 연산 (`openssl_tls_client_socket.cpp`, `openssl_tls_server_socket.cpp`, `openssl_dtls_client_socket.cpp`, `openssl_dtls_server_socket.cpp`).
  * **Server Socket Adapter**: OpenSSL server socket instance를 기존 network loop에 binding하는 adapter 연산 (`openssl_server_socket_adapter.cpp`).
  * **OpenSSL Engine Abstraction & SDK**: OpenSSL 공통 pipeline 및 interface wrapping (`openssl_tls.cpp`, `sdk.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **SSL Context & Engine Management (`openssl_tls_context.cpp`, `openssl_tls.cpp`)**:
  * `SSL_CTX` 생명주기 관리, CA 인증서 검증 load 및 C++11 wrapper 객체 관리 연산.
* **TLS Socket Operations (`openssl_tls_client_socket.cpp`, `openssl_tls_server_socket.cpp`)**:
  * `SSL_connect`, `SSL_accept` 기반 Non-blocking TLS Handshake 및 비동기 Read/Write 연산 처리.
* **DTLS Socket Implementation (`openssl_dtls_client_socket.cpp`, `openssl_dtls_server_socket.cpp`)**:
  * UDP 기반 Datagram TLS (DTLS) session wrapping 및 Handshake 연산 처리.
* **Server Adapter Integration (`openssl_server_socket_adapter.cpp`)**:
  * 비동기 server socket 연결 수신 시 OpenSSL SSL session 자동 binding 연산 수행.

---

### 3. 핵심 동작 mechanism

* **OpenSSL Handshake & Session Flow (`openssl_tls_context.cpp`, `openssl_tls_client_socket.cpp`)**:
  * `openssl_tls_context` 생성 및 인증서/키 load -> client/server socket binding (`openssl_tls_client_socket` / `openssl_tls_server_socket`) -> `SSL_do_handshake` 호출 및 Handshake 완료 -> 암호화된 stream Read/Write 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `openssl_tls_client_socket.cpp` 내 Non-blocking `SSL_ERROR_WANT_READ` / `SSL_ERROR_WANT_WRITE` 재시도 handling 보완 | High | 미진행 |
| **#2** | `openssl_tls_context.cpp` 내 인증서 load 실패 및 `SSL_CTX_new` Null Pointer 예외 처리 확인 | High | 미진행 |
| **#3** | `openssl_dtls_server_socket.cpp` 내 DTLS Cookie Exchange 및 Replay Attack 방지 logic 검증 | High | 미진행 |
| **#4** | `openssl_server_socket_adapter.cpp` 내 비동기 session 종료 시 `SSL_free` / `SSL_shutdown` 메모리 leak 확인 | Medium | 미진행 |
| **#5** | `openssl_tls.cpp` 내 ALPN (Application-Layer Protocol Negotiation) protocol 선택 연산 유효성 검토 | Low | 미진행 |
