## QUIC (Quick UDP Internet Connections) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 9000(QUIC Transport Protocol) 및 RFC 9001(QUIC TLS Securing) 표준 규격을 준수하여 UDP 기반의 신뢰성 있고 저연차(Low Latency) 전송 layer 연산을 수행하는 C++11 구현 module.
* **주요 기능**:
  * **QUIC frame parsing 및 생성**: ACK, STREAM, CRYPTO, PING, PADDING, RESET_STREAM, STOP_SENDING, NEW_CONNECTION_ID, NEW_TOKEN, CONNECTION_CLOSE 등 frame 단위 builder/parser 구현.
  * **QUIC packet layer 제어**: Initial, 0-RTT, Handshake, 1-RTT, Retry, Version Negotiation packet 구조 구성 및 binary encoding/decoding.
  * **session 및 stream 관리**: `quic_session` 및 `quic_streams`를 통한 단방향/양방향 stream 상태 관리 및 session life-cycle 처리.
  * **HTTP/3 연동 layer**: HTTP/3 stream frame 처리 지원 (`quic_frame_http3_stream`).
  * **packet publishing & header 보호**: `quic_packet_publisher`를 통한 packet 송수신 publishing 및 TLS 보호 layer 연동.

---

### 2. 주요 class 및 module 구조

**QUIC core module 구성**

```cpp
namespace hotplace {

// QUIC session 및 stream 관리
class quic_session;
class quic_streams;

// QUIC packet 및 builder
class quic_packet;
class quic_packet_builder;
class quic_packet_publisher;

// QUIC frame 및 builder
class quic_frame;
class quic_frame_builder;

// HTTP/3 mapping frame
class quic_frame_http3_stream;

}  // namespace hotplace

```

---

### 3. 핵심 동작 mechanism

* **packet 및 frame builder 구조 (`quic_packet_builder`, `quic_frame_builder`)**:
  * 각 packet 타입(Initial, Handshake, 1-RTT 등) 및 frame type을 builder pattern으로 조합하여 binary stream 생성.
* **TLS 1.3 기반 handshake 연동 (`quic_packet_initial`, `quic_packet_handshake`)**:
  * QUIC CRYPTO frame을 통해 TLS 1.3 handshake message(`tls_extension_quic_transport_parameters`)를 전달하고 header 보호(Header Protection) 및 1-RTT 키 파생 연동.
* **stream multiplexing (`quic_streams`)**:
  * 단일 QUIC 연결 내에서 독립적인 여러 stream 데이터를 병렬 처리하며, 흐름 제어 및 RESET_STREAM / STOP_SENDING frame 제어 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-QUIC-01** | `quic_packet_1rtt` 내 Packet Number encoding/decoding(Header Protection 적용) 연산 단위 테스트 추가 | High | 미진행 |
| **TODO-QUIC-02** | `quic_frame_ack` 처리 시 ACK Range parsing 유효성 검사 및 둔감화(Ack Eliciting) logic 구현 | High | 미진행 |
| **TODO-QUIC-03** | `quic_streams` module 내 stream 수량 제한(Max Streams) 및 흐름 제어(Flow Control Window) monitoring 강화 | Medium | 미진행 |
| **TODO-QUIC-04** | `quic_packet_retry` 및 `quic_packet_0rtt` packet에 대한 검증 및 예외 처리 logic 보완 | Medium | 미진행 |
| **TODO-QUIC-05** | `quic_frame_http3_stream` 내 HTTP/3 QPACK header 압축 연동 interface 정립 | Low | 미진행 |
