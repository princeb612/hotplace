## Network Server 핵심 아키텍처 및 session 제어 module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 네트워크 server 인프라 구축, TCP/IP socket connection listening, session life-cycle 관리 및 protocol dispatch core module.
* **주요 기능**:
  * **Network Server Core**: socket binding, 포트 binding, client connection 수신 및 server 설정 적용 (`network_server.cpp`, `network_server.hpp`, `server_conf.cpp`).
  * **Session & Connection Manager**: session 생성, 유지보수, cleanup 및 전체 client connection 추적 (`network_session.cpp`, `network_session.hpp`, `network_session_manager.cpp`).
  * **Protocol Parsing & Stream Control**: 수신 바이트 stream parsing, protocol binding 및 데이터 입출력 stream abstraction (`network_protocol.cpp`, `network_protocol_group.cpp`, `network_stream.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Network Server Engine & Configuration (`network_server.cpp`, `server_conf.cpp`)**:
  * IP/Port binding, Socket listen 연산 및 Server Config parameter(Max Connections, Timeout) 적용.
* **Session Lifecycle & Session Manager (`network_session.cpp`, `network_session_manager.cpp`)**:
  * 개별 client connection 상태 관리, Connection Timeout 및 Idle Session cleanup 연산.
  * Unique Session ID mapping 및 Thread-safe session lookup/제거 연산.
* **Protocol Handling & Stream Pipeline (`network_protocol.cpp`, `network_stream.cpp`)**:
  * Stream 읽기/쓰기 바이트 buffer링 및 protocol parser 연동.

---

### 3. 핵심 동작 mechanism

* **Client Connection Accept Flow (`network_server.cpp`, `network_session_manager.cpp`)**:
  * client 접속 요청 수신 -> `network_server` accept 호출 -> 신규 `network_session` 생성 -> `network_session_manager` session 등록.
* **Stream Read & Protocol Processing (`network_stream.cpp`, `network_protocol.cpp`)**:
  * socket 바이트 수신 -> `network_stream` buffer 저장 -> binding된 상위 protocol Layer (`http1`, `http2`, `http3`) dispatch 및 parsing 연산 수행

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `network_server.cpp` 내 accept loop error 발생 시 FD leak 예외 처리 강화 | High | 미진행 |
| **#2** | `network_session_manager.cpp` 내 비동기 session cleanup 시 data race 및 dangling pointer 검증 | High | 미진행 |
| **#3** | `network_stream.cpp` 내 Ring Buffer overflow 및 Boundary condition handling 확인 | Medium | 미진행 |
| **#4** | `server_conf.cpp` 내 설정 파일 validation 및 invalid input handling 보완 | Medium | 미진행 |
| **#5** | `network_protocol_group.cpp` 내 멀티 protocol routing performance profiling 검토 | Low | 미진행 |
