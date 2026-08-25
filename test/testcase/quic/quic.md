## QUIC / HTTP/3 module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: QUIC(RFC 9000, RFC 9369) 전송 protocol 및 QUIC 기반 TLS 1.3 packet 보호(RFC 9001), HTTP/3 연산 지원 module.
* **주요 기능**:
  * **QUIC packet parsing 및 빌드**: Initial, Handshake, 0-RTT, 1-RTT packet framing 연산.
  * **TLS 1.3 / QUIC Crypto binding**: QUIC 전용 TLS 1.3 Key Schedule 파생 및 Header Protection 연산 (`testcase_rfc9001.cpp`).
  * **표준 RFC test vector 검증**: RFC 9000 core, RFC 9001 보안, RFC 9369 v2 protocol 버전 호환성 검증.
  * **HTTP/3 및 PCAP 검증**: HTTP/3 캡처 traffic YML test vector parsing 및 단위 테스트 (`testvector_pcap_http3.yml`).

---

### 2. protocol별 핵심 구현 영역 및 기술 요소

* **QUIC core frame 제어 (`testcase_rfc9000.cpp`, `testcase_construct_quic.cpp`)**:
  * Variable-Length Integer (VLI) encoding/decoding 및 ACK, STREAM, CRYPTO frame 조립.
  * Connection ID parsing 및 packet 구조체 가공.
* **QUIC packet 보호 및 header 암호화 (`testcase_rfc9001.cpp`)**:
  * QUIC v1/v2 Secret 파생 및 Header Protection Mask 연산.
  * PN(Packet Number) decoding 및 AEAD 암호화/복호화 연산.
* **1-RTT 데이터 전송 및 DTLS/QUIC 확장 (`testcase_construct_1rtt.cpp`, `testcase_rfc9369.cpp`)**:
  * Handshake 완료 후 1-RTT Application Data packet 생성 연산.
  * QUIC v2 (RFC 9369) 변경사항 및 버전 협상(Version Negotiation) 호환 검증.
* **HTTP/3 및 packet traffic debugging (`testvector_pcap_http3.yml`, `testvector_pcap.cpp`)**:
  * QPACK encoding 및 HTTP/3 frame traffic parsing 분석.
  * YML 기반 PCAP dump 데이터와 비교 검증 interface 제공.

---

### 3. 핵심 동작 mechanism

* **QUIC handshake & CRYPTO frame 구성 (`testcase_quic.cpp`)**:
  * TLS 1.3 handshake message를 QUIC CRYPTO frame으로 캡슐화하여 전달.
* **Header Protection & Packet Protection (`testcase_rfc9001.cpp`)**:
  * Sample 데이터 추출 후 AES-ECB / ChaCha20 연산으로 Header Mask 생성 및 PN 복호화.
* **RFC 9369 QUIC v2 호환성 검증 (`testcase_rfc9369.cpp`)**:
  * QUIC v1과 v2 packet 타입, Header Formats 및 Key 파생 Salt 값 상이점 검증.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `testcase_rfc9001.cpp` 내 Header Protection Mask 생성 및 PN 복호화 예외 처리 강화 | High | 미진행 |
| **#2** | `testcase_construct_1rtt.cpp` 기반 Short Header packet AEAD decryption 유효성 확인 | High | 미진행 |
| **#3** | `testcase_rfc9369.cpp` QUIC v2 Salt 적용 시 v1/v2 전환 및 Version Negotiation handling 구현 | Medium | 미진행 |
| **#4** | `testvector_pcap_http3.yml` 데이터 활용 QPACK decoder stream error 예외 제어 보완 | Medium | 미진행 |
| **#5** | Variable-Length Integer encoding 경계값 overflow test case 추가 | Low | 미진행 |
