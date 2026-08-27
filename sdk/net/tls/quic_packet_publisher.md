## QUIC Packet Publisher module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: QUIC 프로토콜(QUICv1, QUICv2) 통신 세션에서 생성된 여러 프레임(Frame) 및 패킷(Packet)을 패킷 크기 제한 및 MTU 조건에 맞추어 조각화(Fragmentation), 캡슐화(Encapsulation)하여 전송 버퍼로 송출하는 게시(Publishing) 제어 module.
* **주요 기능**:
  * **Frame 취합 및 Packet Encapsulation**: 큐(Queue)에 대기 중인 QUIC Frame을 수집하여 Protection Space별 QUIC Packet으로 구성 및 전송 버퍼로 게시.
  * **Path MTU 및 Packet Size 제어**: PMTUD(Path MTU Discovery) 연동 및 QUIC 기본 payload 제한(예: Initial 1200 bytes)을 준수하도록 동적 사이즈 제어.
  * **Protection Space 계층 연동**: Initial, Handshake, Application Data 계층별 패킷 세분화 처리 및 `tls_protection` 암호화/Header Protection 단계 전송 준비 수행.

---

### 2. 핵심 구현 영역 및 기술 요소

* **Packet Packaging 및 Buffer 관리 (`quic_packet_publisher.cpp`, `testcase_construct_quic.cpp`)**:
  * 단일/다중 QUIC Frame을 빌드하여 제한된 버퍼 크기 내에 패킹하고 하위 소켓 네트워크 계층으로 전달하는 전달 파이프라인 제어.
  * `add()`, `add_stream()` 메서드를 통한 메인 컨트롤/QPACK/HTTP3 프레임 구성 연동 지원.
* **Protection Space별 Packet 분할 (`quic_packet_publisher.hpp`, `testcase_construct_quic.cpp`)**:
  * Handshake 진행 상태에 맞춰 Initial, Handshake, Application Protection Space 패킷을 독립적으로 퍼블리싱 및 스케줄링.
  * `for_each_pkn()`을 이용해 각 Space별 PKN(Packet Number) 할당 내역 추적 및 ACK 제어 연동.
* **Packet Protection 연동 (`tls_protection_calc.cpp`)**:
  * `tls_protection`에서 생성된 Key Schedule(Initial/Handshake/Application Key, IV, Header Protection Key)을 기반으로 암호화 직전 패킷 구조 형성.

---

### 3. 핵심 동작 mechanism

* **QUIC Frame/Packet 송출 파이프라인 (`quic_packet_publisher::publish`)**:
  * 전송 대기 중인 QUIC Frame들을 순회하며 지정된 `max_packet_size` 오버플로우 발생 여부를 체크.
  * 패킷 크기 초과 시 단일 UDP Datagram 내 분할(Fragment)을 수행하고, 유효 패킷을 생성하여 소켓 버퍼로 게시.
  * `quic_pad_packet` 플래그 설정 시 `max_udp_payload_size`(1200 bytes)에 맞추어 패키징 패딩(PADDING Frame) 자동 증분 처리.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-QPP-01** | `testcase_construct_quic.cpp` 내 **NEW_SESSION_TICKET**(NST), **HANDSHAKE_DONE**, **NEW_TOKEN**, **NEW_CONNECTION_ID** 프레임 게시 시 패킷 세그먼트 및 ACK 수신 동작 정교화 검증 | High | 진행 중 | `testcase_construct_quic.cpp`<br> |
| **TODO-QPP-02** | Initial 및 Handshake packet을 단일 UDP Datagram으로 합치는 **QUIC Packet Coalescing** 기능 보완 | High | 미진행 | `quic_packet_publisher.cpp`<br> |
| **TODO-QPP-03** | `quic_pad_packet` 플래그 세팅 시 `max_udp_payload_size`(1200 bytes) 맞춤 **PADDING Frame 자동 패킹 logic** 최적화 | Medium | 진행 중 | `testcase_construct_quic.cpp`<br> |
| **TODO-QPP-04** | Path MTU Discovery(PMTUD) 측정 결과 변경 시 `max_packet_size` 동적 업데이트 연동 | Medium | 진행 중 | MTU 최적화 |
| **TODO-QPP-05** | HTTP/3 QPACK Encoder/Decoder Stream 및 Data Frame 대량 전송 시 Publisher performance benchmark 테스트 케이스 작성 | Low | 미진행 | `testcase_construct_quic.cpp`<br> |
