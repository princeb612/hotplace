## HTTP/3 frame 및 protocol module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: QUIC protocol 기반 RFC 9114 규격 HTTP/3 frame parsing, 빌드 및 타입 제어 module.
* **주요 기능**:
  * **HTTP/3 Frame 직렬화/역직렬화**: DATA, HEADERS, CANCEL_PUSH, SETTINGS, PUSH_PROMISE, GOAWAY, MAX_PUSH_ID, PRIORITY_UPDATE, ORIGIN, METADATA frame encoding/decoding (`http3_frame*.cpp`).
  * **Variable-Length Integer (Varint) 기반 Type & Length 처리**: QUIC protocol 특성에 맞춘 Variable-Length Integer frame type 및 길이 parsing (`http3_frame.cpp`).
  * **Frame Builder 연산**: builder pattern 기반 HTTP/3 frame 조립 및 바이트 stream 생성 (`http3_frame_builder.cpp`, `http3_frame_builder.hpp`).
  * **Unknown Frame Handling**: 표준 외 정의되거나 확장된 frame 호환을 위한 Unknown Frame encoding/decoding 연산 (`http3_frame_unknown.cpp`, `http3_frame_unknown.hpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **QUIC Varint 및 HTTP/3 Frame Header Parsing (`http3_frame.cpp`, `http3_frame_*.cpp`)**:
  * HTTP/3 frame Type 및 Length field의 Variable-Length Integer 바이트 decoding 연산 수행.
  * DATA 및 HEADERS frame의 Request Stream 전송 제어 연산.
* **Control Stream & Extension Frames (`http3_frame_settings.cpp`, `http3_frame_priority_update.cpp`, `http3_frame_origin.cpp`)**:
  * QPACK Encoder Stream 및 Control Stream 연결 상태 연동 및 parameter 적용 연산
  * SETTINGS frame을 통한 QPACK 및 QUIC session parameter 교환 연산.
  * RFC 9218 기반 PRIORITY_UPDATE frame 및 ORIGIN, METADATA 확장 frame 처리 연산.
* **Push Control & Termination Frames (`http3_frame_cancel_push.cpp`, `http3_frame_max_push_id.cpp`, `http3_frame_goaway.cpp`)**:
  * Server Push 제어를 위한 CANCEL_PUSH 및 MAX_PUSH_ID frame handling.
  * Connection Graceful Shutdown을 위한 GOAWAY frame 연산.

---

### 3. 핵심 동작 mechanism

* **Variable-Length Frame Parsing Flow (`http3_frame.cpp`, `http3_frame_builder.cpp`)**:
  * 수신 QUIC Stream 바이트 읽기 -> Varint Type/Length decoding -> Type에 mapping되는 `http3_frame_*` 객체 생성 및 validation 연산 수행.
* **Control Stream Initialization & Settings Exchange (`http3_frame_settings.cpp`)**:
  * Unidirectional Control Stream 오픈 -> SETTINGS frame 직렬화 후 전송 -> 상대방 Control Stream 수신 및 QPACK parameter 적용 연산.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-H3-01** | `http3_frame.cpp` 내 QUIC Varint decoding 시 입력 buffer Boundary 초과 예외 처리 보완 | High | 미진행 |
| **TODO-H3-02** | `http3_frame_settings.cpp` http3_frame_settings.cpp 내 Control Stream 중복 SETTINGS 수신 처리 및 QPACK Dynamic Table sync 검증 | High | 미진행 |
| **TODO-H3-03** | `http3_frame_priority_update.cpp` 내 RFC 9218 Priority Element ID boundary validation 검증 | Medium | 미진행 |
| **TODO-H3-04** | `http3_frame_unknown.cpp` 내 미지원 frame 수신 시 Stream 무시(Ignore) mechanism 검증 | Medium | 미진행 |
| **TODO-H3-05** | `http3_frame_metadata.cpp` 내 확장 METADATA frame 바이트 boundary 체크 연산 적용 검토 | Low | 미진행 |
