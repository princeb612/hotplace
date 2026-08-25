## HPACK (HTTP/2 Header Compression) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: HTTP/2 표준(RFC 7541) 기반 header 압축/해제 및 정적/동적 table 관리 연산 module.
* **주요 기능**:
  * **Static Table parsing 및 조회**: 사전 정의된 Index 기반 HTTP header 이름 및 값 lookup (`hpack_static_table.cpp`, `hpack_static_table.hpp`).
  * **Dynamic Table 수명주기 제어**: runtime 수신 header encoding/decoding 상태 유지, FIFO 기반 메모리 크기 제한 및 Eviction 처리 (`hpack_dynamic_table.cpp`, `hpack_dynamic_table.hpp`).
  * **HPACK Encoder 연산**: Primitive Type(Integer, Literal) encoding, Huffman Coding 및 Header Block 생성 (`hpack_encoder.cpp`, `hpack_encoder.hpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Static Table lookup 연산 (`hpack_static_table.cpp`, `hpack_static_table.hpp`)**:
  * RFC 7541에 규정된 61개 정적 header 항목에 대한 O(1) Index mapping 및 Key-Value 검색 기능 제공.
* **Dynamic Table FIFO 관리 및 Eviction (`hpack_dynamic_table.cpp`, `hpack_dynamic_table.hpp`)**:
  * 동적 table 용량(SETTINGS_HEADER_TABLE_SIZE) 초과 시 오래된 Entry를 자동으로 축출하는 Eviction mechanism 구현.
  * Entry 크기 계산 시 overhead(32바이트)를 포함한 정확한 바이트 가중치 연산 적용.
* **HPACK Header Encoding 및 representation (`hpack_encoder.cpp`, `hpack_encoder.hpp`)**:
  * Indexed Header Field, Literal Header Field (Incremental Indexing / Without Indexing / Never Indexed) 표현 방식 지원.
  * Variable-length Integer encoding 및 Prefix 비트 masking 연산 수행.

---

### 3. 핵심 동작 mechanism

* **Dynamic Table Entry Eviction (`hpack_dynamic_table.cpp`)**:
  * 신규 Header Entry 추가 시 현재 table 사용량이 최대 용량을 초과하면 FIFO 순서로 Tail 영역부터 Evict 연산 수행.
* **HPACK Integer & Literal Representation (`hpack_encoder.cpp`)**:
  * Prefix 비트에 맞춰 정수형 encoding을 수행하고, Static/Dynamic Table Index mapping 여부에 따라 Literal representation 선택 encoding.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `hpack_dynamic_table.cpp` Table Size Update 시 용량 축소 과정 overflow 및 Eviction 예외 처리 보완 | High | 미진행 |
| **#2** | `hpack_encoder.cpp` 내 Huffman Encoding encoder 구현 유효성 및 경계 비트 바이트 alignment 확인 | High | 미진행 |
| **#3** | `hpack_static_table.cpp` 정적 table 범위 초과 Index 접근 시 OOB 처리 검증 | Medium | 미진행 |
| **#4** | Dynamic Table Entry 추가 시 32바이트 Overhead 가산 기준 정확성 검증 | Medium | 미진행 |
| **#5** | `hpack_encoder.cpp` 내 N-bit Prefix Integer encoding 대용량 값 입력 시 buffer overflow 예외 처리 확인 | Low | 미진행 |
