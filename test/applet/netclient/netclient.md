## Network Client Test Module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: TCP, UDP, TLS, DTLS, QUIC protocol별 client socket의 연동 및 송수신 동작 검증을 위한 테스트 module (`test_netclient.cpp`).
* **주요 기능**:
  * **Multi-Protocol Client Testing**: Naive, OpenSSL, Trial 기반 socket의 연결, 데이터 송수신 (`send`, `read`, `more`, `sendto`, `recvfrom`) 연산 테스트.
  * **TLS / DTLS Engine Switching**: OpenSSL SDK 연동 방식 (`openssl_tls_client_socket`, `openssl_dtls_client_socket`)과 내부 구현 방식 (`trial_tls_client_socket`, `trial_dtls_client_socket`) 조건부 비교 테스트.
  * **Stack Allocation Optimization**: OS platform별 stack buffer 할당 (`__GNUC__` VLA (Variable-Length Array) vs `_MSC_VER` `_alloca`) 연산.

---

### 2. 핵심 구현 영역 및 기술 요소

* **TCP / UDP Client Testing (`tcp_client`, `udp_client`)**:
  * Command line option flags에 따라 naive 또는 trial socket 객체 생성 및 연결 연산.
  * `more_data` 반환 code에 따른 stream buffer 누적 처리 연산.
* **TLS Client Testing (`tls_client`, `tls_client2`)**:
  * **`tls_client`**: `SSL_CTX` 생성 및 `openssl_tls` wrapper 연동 기반 TLS 1.2 / 1.3 handshake 및 송수신 검증.
  * **`tls_client2`**: OpenSSL CTX 직접 노출 없이 `trial_tls_client_socket`을 이용한 TLS session 연산.
* **DTLS Client Testing (`dtls_client`, `dtls_client2`)**:
  * **`dtls_client`**: OpenSSL 기반 DTLS client socket 연산.
  * **`dtls_client2`**: Trial 기반 DTLS client socket 연산 및 record publisher option (fragment size, multi handshakes) 설정 검증.

---

### 3. 핵심 동작 mechanism

* **Client Socket Lifecycle & Test Flow (`test_netclient.cpp`)**:
  * Command line option parsing -> socket 객체 생성 (Naive / OpenSSL / Trial) -> `connect` 또는 `open` 실행 -> 송수신 loop 수행 (`send` / `read` / `more`) -> `__finally2` block 내 socket `close`, resource cleanup 및 test case 결과 기록 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `quic_client()` 내 tls_composer QUIC feature, trial_quic_client_socket 및 trial_quic_server_socket 연동 구현 | High | 미진행 |
| **#2** | `tcp_client()`, `tls_client()` 내 VLA (`char buffer[option.bufsize]`) 및 `_alloca` 사용 시 stack overflow 가능성 검증 및 dynamic buffer 대체 검토 | High | 미진행 |
| **#3** | `dtls_client2()` 내 `trial_dtls_client_socket` 미구현 stub 해제 후 actual handshake 연산 검증 | Medium | 미진행 |
| **#4** | `tls_client()` 내 `SSL_CTX_free` 및 `openssl_cleanup` 호출 시 resource leak 여부 static analysis 검증 | Low | 미진행 |
