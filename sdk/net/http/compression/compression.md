## HTTP Header Compression 공통/기반 module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**:
  * HPACK/QPACK 등 HTTP header 압축 algorithm의 공통 추상화 layer 및 정적/동적 table, stream 압축 기반 구조 연산 module.
  * HPACK 및 QPACK module의 상위 Base Data Structure 및 추상화 layer 역할 수행
* **주요 기능**:
  * **공통 타입 및 데이터 구조 정의**: header 압축 연산용 공통 타입, flag, Key-Value 구조체 및 열거형 정의 (`types.hpp`).
  * **HTTP Static/Dynamic Table 공통 구현**: header lookup을 위한 정적 table 및 동적 table 기초 메모리 제어 (`http_static_table.cpp`, `http_dynamic_table.cpp`).
  * **Header Compression 추상화 interface**: header encoding/decoding facade 및 stream 기반 입출력 연산 지원 (`http_header_compression.cpp`, `http_header_compression_stream.hpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **공통 데이터 타입 및 구조체 정의 (`types.hpp`)**:
  * HTTP/2 및 HTTP/3 header 압축에서 공통으로 활용되는 Header Entry, Table Size, Indexing Mode 정의.
* **HTTP Static & Dynamic Table 공통 logic (`http_static_table.cpp`, `http_dynamic_table.cpp`)**:
  * 정적 table 키-값 lookup algorithm 기반 제공.
  * 동적 table 메모리 boundary 관리 및 Entry 추가/축출(Eviction) 기본 mechanism 구현.
* **Header Compression & Stream 추상화 (`http_header_compression.cpp`, `http_header_compression_stream.hpp`)**:
  * protocol 독립적인 Header Block parsing 및 stream interface 처리.
  * encoding/decoding 상태 추적 및 stream 입출력 pipeline 연동.

---

### 3. 핵심 동작 mechanism

* **Header Table Lookup & Dynamic Entry Management (`http_dynamic_table.cpp`, `http_static_table.cpp`)**:
  * 정적/동적 table 내 일치하는 header(Name/Value) 검색 후 Index 반환 또는 신규 Entry 동적 추가.
* **Stream-based Encoding/Decoding Pipeline (`http_header_compression_stream.hpp`)**:
  * 바이트 stream 단위로 들어오는 header block 데이터를 차례대로 encoding/decoding state machine으로 처리.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-HC-01** | `http_dynamic_table.cpp` 내 동적 table 용량 제어 시 memory allocation 예외 처리 보완 | High | 미진행 |
| **TODO-HC-02** | `http_header_compression_stream.hpp` stream pipeline 경계 비트 바이트 alignment 확인 | High | 미진행 |
| **TODO-HC-03** | `types.hpp` 내 enum/struct 정의 확장성 및 C++11 type safety 검증 | Medium | 미진행 |
| **TODO-HC-04** | `http_static_table.cpp` 무효한 index 참조 시 safe access 예외 handling 보완 | Medium | 미진행 |
| **TODO-HC-05** | `http_header_compression.cpp` 대용량 header block 입력 시 buffer overflow 검증 | Low | 미진행 |
