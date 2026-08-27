## server 애플릿(Server Applet) - published by Gemini

---

### 1. tcpserver1 (Multiplexer interface 기반 TCP server)

* **주요 역할**: I/O Multiplexer(IOCP/Epoll 등) 기반 Event Loop 제어를 이용한 비동기 TCP server 기본 동작 구현.
* **핵심 동작 mechanism**:
  * Multiplexer 객체에 TCP Listening Socket 등록 후 Event Loop 진입.
  * client 접속 및 Read/Write 이벤트 발생 시 Handler Callback 수행.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | Socket Read 이벤트 발생 시 partial read/write 처리 handling 보완 | High | 미진행 |
| **#2** | Multiplexer Shutdown 시 client session cleanup 처리 검증 | Medium | 미진행 |

---

### 2. tcpserver2 (Network Server interface 기반 TCP server)

* **주요 역할**: `network_server` high-level 추상화 interface를 활용한 캡슐화된 TCP server 동작 구현.
* **핵심 동작 mechanism**:
  * `network_server` 객체 생성 및 포트/protocol 설정 후 `start()` 호출.
  * 내부 thread pool 및 socket life-cycle을 추상화된 server 이벤트 protocol로 제어.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `network_server` session 파괴 시 메모리 누수 유무 검증 | High | 미진행 |
| **#2** | 동시 접속 자원 제한 (Max Connection) 설정 interface 적용 | Medium | 미진행 |

---

### 3. udpserver1 (Multiplexer interface 기반 UDP server)

* **주요 역할**: I/O Multiplexer 제어를 통한 비연결성(Connectionless) UDP socket 이벤트 처리.
* **핵심 동작 mechanism**:
  * UDP socket을 Multiplexer에 등록하고 데이터 수신 Read 이벤트 대기.
  * `recvfrom` / `sendto` 연산을 통한 Datagram 동기 처리 및 socket 이벤트 dispatch.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | UDP Datagram buffer overflow 발생 시 packet Drop handling 강화 | High | 미진행 |
| **#2** | Multiplexer 내 Client IP/Port 관리용 데이터 구조 보완 | Medium | 미진행 |

---

### 4. udpserver2 (Network Server interface 기반 UDP server)

* **주요 역할**: `network_server` 추상화 layer 기반 UDP Datagram server 구현.
* **핵심 동작 mechanism**:
  * UDP server 속성으로 `network_server` 초기화 후 서비스 실행.
  * Datagram 수신 및 송신 핸들러 연결을 통한 비동기 UDP session 제어.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | 비대칭 UDP 송수신 traffic 시 thread pool 병목 현상 점검 | High | 미진행 |
| **#2** | `network_server` stop 시 pending datagram dump 처리 | Low | 미진행 |

---

### 5. tlsserver (Network Server interface 기반 TLS server)

* **주요 역할**: OpenSSL 및 Hotplace 보안 framework 연동 TLS(Transport Layer Security) 암호화 server 구현.
* **핵심 동작 mechanism**:
  * SSL Context 초기화, 인증서(`cert.pem`) 및 개인키(`key.pem`) loading.
  * TLS Handshake 수행 및 암호화 채널(Encrypted Channel)을 통한 Read/Write 연산.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | TLS Handshake 실패 시 SSL Error Code 상세 logging 보완 | High | 미진행 |
| **#2** | TLS 1.2 / TLS 1.3 Ciphersuite 호환성 및 DH Parameter 세팅 확인 | Medium | 미진행 |

---

### 6. dtlsserver (Network Server interface 기반 DTLS server)

* **주요 역할**: Datagram 기반 TLS(DTLS) 암호화 통신 server 구현.
* **핵심 동작 mechanism**:
  * UDP socket 상에서 DTLS Context를 생성하고 DTLS Cookie Exchange 및 Handshake 연산 수행.
  * packet 손실 및 재전송 timer를 고려한 Secure Datagram 송수신 제어.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | DTLS Handshake Packet Loss 발생 시 Retransmission timer logic 검증 | High | 미진행 |
| **#2** | DTLS Client Cookie Verification 연산 오류 handling 보완 | Medium | 미진행 |

---

### 7. httpserver1 (HTTP Server interface 기반 HTTP/1.1 server)

* **주요 역할**: `http_server` interface 기반 HTTP/1.1 Request/Response protocol parsing 및 정적 resource web server 동작 구현.
* **핵심 동작 mechanism**:
  * HTTP Method(GET, POST 등), URI, Header 및 Body parsing.
  * `index.html`, `signin.html`, `style.css` 정적 routing 및 HTTP Response redering.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | HTTP/1.1 Keep-Alive Connection Timeout 처리 logic 확인 | High | 미진행 |
| **#2** | POST Body parsing 시 Chunked Transfer Encoding 예외 처리 보완 | Medium | 미진행 |

---

### 8. httpserver2 (HTTP Server interface 기반 HTTP/2 server)

* **주요 역할**: `http_server` interface 기반 HTTP/2 binary frame 및 다중화(Multiplexing) 지원 server 구현.
* **핵심 동작 mechanism**:
  * HTTP/2 Frame(SETTINGS, HEADERS, DATA 등) parsing 및 HPACK header 압축 해제.
  * 단일 TCP 연결 상에서 Multi-Stream session dispatch 및 정적 resource 전달.
* **TODO list**:

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-APP-01** | HPACK Dynamic Table Management overflow 예외 처리 검증 | High | 미진행 |
| **TODO-APP-02** | HTTP/2 Stream Flow Control (WINDOW_UPDATE) 제어 연산 확인 | Medium | 미진행 |
