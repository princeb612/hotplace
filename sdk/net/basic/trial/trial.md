## Trial (Transport & TLS/QUIC Engine) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: protocol별(TCP, UDP, TLS, DTLS, QUIC) client/server socket 구현, TLS Handshake Composer 및 Prosumer pattern 기반 비동기 데이터 송수신 pipeline module.
* **주요 기능**:
  * **Transport & Security Socket Abstraction**: TCP/UDP 기초 socket, TLS 보안 socket 및 QUIC socket wrapping 연산 (`trial_tcp_client_socket.cpp`, `trial_tls_client_socket.cpp`, `trial_quic_client_socket.cpp` 등).
  * **TLS & QUIC Handshake Orchestration**: TLS 1.3 및 QUIC Handshake packet 생성 및 state machine 조율 (`tls_composer.cpp`, `tls_composer_tls_handshake.cpp`, `tls_composer_quic_handshake.cpp`).
  * **Prosumer Pattern Data Pipeline**: Producer-Consumer 기반 보안/비보안 데이터 송수신 pipeline 연산 (`client_socket_prosumer.cpp`, `secure_prosumer.cpp`).
  * **Server Adapter Management**: server socket instance wrapping 및 event adapter 제어 (`trial_server_socket_adapter.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Socket Implementations (`trial_*_socket.cpp`)**:
  * TCP/UDP 전송 계층 socket handling 및 Async I/O 연결 연산.
  * OpenSSL SSL/TLS Context 기반 TLS/QUIC session 생성 및 Handshake pipeline 연산.
  * **DTLS Client/Server Socket (`trial_dtls_client_socket.cpp`, `trial_dtls_server_socket.cpp`)**: 현재 미구현 stub 상태로 향후 구현 예정.
* **Handshake Composer (`tls_composer_*.cpp`)**:
  * ClientHello, ServerHello, EncryptedExtensions 등 TLS Handshake message 생성 및 parsing 연산.
  * QUIC Transport Parameters 및 Handshake Crypto Level 연동 parsing.
* **Prosumer Pattern & Adapter (`secure_prosumer.cpp`, `trial_server_socket_adapter.cpp`)**:
  * buffer 메모리 기반 socket 데이터 생산자/소비자(Producer/Consumer) 송수신 pipeline 제어 및 Socket 이벤트 어댑터 mapping.

---

### 3. 핵심 동작 mechanism

* **Secure Connection & Handshake Flow (`trial_tls_client_socket.cpp`, `tls_composer.cpp`)**:
  * socket 연결 수신 -> `tls_composer` Handshake message 생성 -> TLS/QUIC Handshake 수행 (`tls_composer_tls_handshake` / `tls_composer_quic_handshake`) -> Handshake 완료 후 `secure_prosumer` 데이터 송수신 pipeline 진입 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-TRIAL-01** | `tls_composer_quic_handshake.cpp` 내 QUIC Transport Parameters validation 및 Boundary check 보완 | High | 미진행 |
| **TODO-TRIAL-02** | `secure_prosumer.cpp` 내 비동기 데이터 송수신 buffer 접근 시 Data Race 및 Race Condition 예외 처리 확인 | High | 미진행 |
| **TODO-TRIAL-03** | `trial_dtls_client_socket.cpp` 및 `trial_dtls_server_socket.cpp` 내 DTLS socket binding, Handshake 및 Packet Reordering 구현 | High | 미진행 |
| **TODO-TRIAL-04** | `trial_quic_server_socket.cpp` 내 Connection ID (CID) Routing 및 Demuxing 연산 유효성 검증 | Medium | 미진행 |
| **TODO-TRIAL-05** | `trial_server_socket_adapter.cpp` 내 socket close 시 resource leak 및 dangling pointer 검증 | Low | 미진행 |
