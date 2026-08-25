## TLS / DTLS module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: TLS 1.2, TLS 1.3, DTLS 1.2, DTLS 1.3 및 PQ(Post-Quantum) algorithm(ML-KEM)을 포함하는 전송 계층 보안 protocol parsing 및 생성 연산 module.
* **주요 기능**:
  * **TLS/DTLS record & handshake 제어**: record packet parsing, DTLS 1.2/1.3 handshake 재조합(`testcase_dtls_record_arrange.cpp`) 및 Alert 처리.
  * **표준 test vector 및 RFC 8448 검증**: RFC 8448 handshake test case (`testcase_rfc8448_2.cpp` ~ `7.cpp`) 및 PCAP 기반 traffic 검증 지원.
  * **암호화 및 post-quantum(PQ) 확장**: AEAD 연산(`testcase_tls12_aead.cpp`), Pre-Master Secret 계산 및 ML-KEM encoding (`testcase_mlkem_encoding.cpp`) parser 지원.
  * **ClientHello 및 HelloRetryRequest 처리**: ClientHello dump(`dump_clienthello.cpp`) 및 HelloRetryRequest 생성/검증(`testcase_helloretryrequest.cpp`).

---

### 2. protocol별 핵심 구현 영역 및 기술 요소

* **TLS 1.3 키 파생 및 상태 전이 (`testcase_understand_tls13.cpp`, `testcase_rfc8448_*.cpp`)**:
  * ClientHello부터 Finished 단계까지 Handshake Context transcript hash 기반 Secret 파생(Early, Handshake, Master Secret) 연산 검증.
  * RFC 8448 표준 test vector와 1:1 비교를 통한 handshake 키 schedule 구현 정확성 확보.
* **DTLS 1.2/1.3 신뢰성 mechanism (`testcase_dtls_record_arrange.cpp`, `testcase_understand_dtls.cpp`)**:
  * 비신뢰성 UDP 매체 특성을 보완하기 위한 Epoch / Sequence Number 기반 record 순서 재배치 및 단편화(Fragmentation) 재조합 logic.
  * DTLS 1.3 명세에 맞춘 ACK frame 및 재전송 timer 상태 제어.
* **post-quantum cryptography(PQC) 확장 및 AEAD 처리 (`testcase_mlkem_encoding.cpp`, `testcase_tls12_aead.cpp`)**:
  * ML-KEM(Kyber) 기반 KeyShare 확장 encoding/decoding 및 TLS 1.3 binding parsing.
  * AES-GCM, ChaCha20-Poly1305 등 AEAD 암호화 방식의 Explicit/Implicit Nonce 구성 및 AAD(Additional Authenticated Data) 연산 처리.
* **handshake 예외 제어 및 debugging (`testcase_helloretryrequest.cpp`, `dump_clienthello.cpp`)**:
  * 그룹 미지원 상황에서의 HelloRetryRequest(HRR) 재요청 시 KeyShare 교체 연산.
  * binary stream에서 ClientHello payload를 parsing하여 Extension 목록 및 Ciphersuite 정보를 분석하는 debugging interface 제공.

---

### 3. 핵심 동작 mechanism

* **TLS/DTLS record 및 handshake 생성 (`testcase_construct_*.cpp`)**:
  * C++11 구조를 활용하여 TLS 및 DTLS 1.2/1.3 record layer와 Handshake message 구조체 구성 및 encoding 연산 수행.
* **DTLS 단편화 및 재조합 (`testcase_dtls_record_arrange.cpp`)**:
  * 비신뢰성 UDP 매체 특성에 따른 Sequence Number 기반 단편화(Fragment) 및 순서 재배치 handling.
* **RFC 8448 & ML-KEM 검증 (`testcase_rfc8448_*.cpp`, `testcase_mlkem_encoding.cpp`)**:
  * TLS 1.3 표준 검증용 벡터 기반 Secret 파생 및 차세대 양자 내성 암호화(ML-KEM) encoding 테스트.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `testcase_mlkem_encoding.cpp` 내 ML-KEM 키 교환 및 TLS 1.3 KeyShare 확장 parsing 유효성 검증 | High | 미진행 |
| **#2** | `testcase_dtls_record_arrange.cpp` 기반 DTLS 1.3 handshake packet 손실 시 재전송 timer logic 검증 | High | 미진행 |
| **#3** | `testcase_tls12_aead.cpp` 내 AES-GCM 및 ChaCha20-Poly1305 AEAD tag 검증 예외 처리 보완 | Medium | 미진행 |
| **#4** | `testcase_helloretryrequest.cpp` 내 HRR 응답 시 KeyShare 재요청 및 Handshake Context 업데이트 logic 확인 | Medium | 미진행 |
| **#5** | `dump_clienthello.cpp` parser 내 Unrecognized Extension debugging logging 정교화 | Low | 미진행 |
