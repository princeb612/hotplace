## HTTP/2 frame 및 session pipeline module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 7540 규격 기반 HTTP/2 binary frame 생성/parsing, session multiplexing 및 server push 제어 module.
* **주요 기능**:
  * **HTTP/2 Frame 직렬화/역직렬화**: DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION, ALT_SVC frame handling (`http2_frame*.cpp`).
  * **Frame Builder facade**: builder pattern 기반 frame header 및 바이트 payload 조립 (`http2_frame_builder.cpp`, `http2_frame_builder.hpp`).
  * **HTTP/2 Session & Stream multiplexing**: 단일 TCP 연결 상에서 stream life-cycle 및 flow control 제어 (`http2_session.cpp`, `http2_session.hpp`).
  * **Server Push 제어**: PUSH_PROMISE frame 연동 및 서브 resource 자원 push pipeline 연산 (`http2_serverpush.cpp`, `http2_serverpush.hpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **binary Frame Header 및 Type-Specific Parsing (`http2_frame.cpp`, `http2_frame_*.cpp`)**:
  * 9바이트 공통 frame header (Length, Type, Flags, Stream ID) parsing 연산.
  * 각 frame type별 payload decoding 및 Flag (END_STREAM, END_HEADERS, ACK 등) 상태 검증.
* **HTTP/2 Session Management (`http2_session.cpp`)**:
  * Connection Preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) 검증 및 session 초기화.
  * Multi-stream 상태 추적, SETTINGS Exchange 및 Stream Flow Control (WINDOW_UPDATE) 관리.
* **Server Push & Protocol Handling (`http2_serverpush.cpp`, `http2_protocol.cpp`)**:
  * client 요청 기반 약속된 response stream 생성 및 PUSH_PROMISE frame encoding.

---

### 3. 핵심 동작 mechanism

* **Frame Parsing & Dispatch Flow (`http2_session.cpp`, `http2_frame_builder.cpp`)**:
  * 수신 바이트 stream parsing -> 9바이트 Frame Header 읽기 -> Type에 해당하는 `http2_frame_*` 객체 생성 -> `http2_session` steering dispatch.
  * HEADERS / CONTINUATION frame 수신 시 hpack_encoder 및 hpack_dynamic_table pipeline으로 Header Block Fragment를 전달하여 압축 해제 연산 수행
* **Stream Flow Control & Window Management (`http2_frame_window_update.cpp`)**:
  * stream 및 Connection 수준의 수신 Window 크기 monitoring -> 바이트 소비 시 WINDOW_UPDATE frame 전송.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `http2_session.cpp` 내 Client Connection Preface 검증 실패 시 GOAWAY 처리 보완 | High | 미진행 |
| **#2** | `http2_frame_headers.cpp` 내 CONTINUATION frame interleaving 발생 시 Protocol Error 처리 강화 | High | 미진행 |
| **#3** | `http2_frame_window_update.cpp` 내 Flow Control Window Overflow 검증 | Medium | 미진행 |
| **#4** | `http2_serverpush.cpp` 내 Push Stream ID 할당 규칙 (짝수 Stream ID) 준수 여부 확인 | Medium | 미진행 |
| **#5** | `http2_frame_settings.cpp` 내 SETTINGS ACK 수신 timer Timeout handling 적용 검토 | Low | 미진행 |
