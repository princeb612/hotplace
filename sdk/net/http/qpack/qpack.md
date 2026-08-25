## QPACK (HTTP/3 Header Compression) module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: HTTP/3 표준(RFC 9204) 기반 header 압축/해제, Encoder/Decoder stream 분리 제어 및 정적/동적 table 연산 module.
* **주요 기능**:
  * **Static Table parsing 및 조회**: RFC 9204 기준 99개 정적 header 항목 Index mapping 및 Key-Value lookup 연산 (`qpack_static_table.cpp`, `qpack_static_table.hpp`).
  * **Dynamic Table 및 절대/상대 Indexing**: Encoder/Decoder stream 상에서 Absolute Index와 Relative Index 간 변환 연산, Capacity 기반 Eviction 처리 (`qpack_dynamic_table.cpp`, `qpack_dynamic_table.hpp`).
  * **QPACK Encoder 연산**: Field Line encoding, Prefix Integer / Literal 표현 연산 및 Encoder Stream 명령어 생성 (`qpack_encoder.cpp`, `qpack_encoder.hpp`).
  * **QPACK SDK facade 및 interface**: QPACK 통합 처리 facade 및 외부 연동 interface 제공 (`qpack_sdk.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Static Table lookup 연산 (`qpack_static_table.cpp`, `qpack_static_table.hpp`)**:
  * RFC 9204 규격의 99개 정적 table 항목에 대한 $O(1)$ 빠른 Index 접근 및 검색 연산 수행.
* **Dynamic Table 및 Index 변환 연산 (`qpack_dynamic_table.cpp`, `qpack_dynamic_table.hpp`)**:
  * HTTP/3 Head-of-Line Blocking 방지를 위한 Absolute Index <-> Relative Index / Post-Base Index 변환 제어.
  * 동적 table 메모리 제한 초과 시 FIFO 방식의 Entry Eviction 및 Entry Count 관리 연산.
* **QPACK Encoder 및 Instruction 생성 (`qpack_encoder.cpp`, `qpack_encoder.hpp`)**:
  * Required Insert Count 및 Base Index 계산을 통한 Field Line encoding.
  * Literal Field Line with Name Reference / Literal Name encoding 연산 지원.
* **QPACK SDK 연동 interface (`qpack_sdk.cpp`)**:
  * HTTP/3 protocol layer와 QPACK Encoder/Decoder 간 가교 역할을 하는 C++11 facade interface.

---

### 3. 핵심 동작 mechanism

* **Index Translation Mechanism (`qpack_dynamic_table.cpp`)**:
  * 동적 table 항목 접근 시 Absolute Index를 기준점(Base)에 따라 Relative Index 및 Post-Base Index로 변환하여 header block encoding 수행.
* **Header Field Encoding & Stream Handling (`qpack_encoder.cpp`, `qpack_sdk.cpp`)**:
  * 입력받은 HTTP/3 header list를 Static/Dynamic Table mapping 여부에 따라 변환하고 Encoder Stream 명령어를 조립하여 전송.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `qpack_dynamic_table.cpp` 내 Relative Index 변환 시 Base Index overflow 및 OOB(Out of Bounds) 예외 처리 강화 | High | 미진행 |
| **#2** | `qpack_encoder.cpp` 내 Required Insert Count 계산 logic 유효성 및 Unacknowledged Entry Limit 검증 | High | 미진행 |
| **#3** | `qpack_sdk.cpp` 내 HTTP/3 Stream cancellation 발생 시 QPACK Dynamic Table reference count cleanup 확인 | Medium | 미진행 |
| **#4** | `qpack_static_table.cpp` 범위 초과 Index 접근 시 safe lookup 예외 처리 보완 | Medium | 미진행 |
| **#5** | `qpack_encoder.cpp` 내 Huffman Encoding 적용 여부 판단 및 비트 parsing 경계 검증 | Low | 미진행 |
