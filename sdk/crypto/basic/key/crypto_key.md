## Crypto Key module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 암호화 키 객체 캡슐화, 키 metadata 관리, 키 검색 및 원시 키 추출 module.
* **주요 기능**:
  * **Key Object Encapsulation**: 키 속성 및 metadata wrapping 연산 (`crypto_key_object.cpp`).
  * **Key Search & Lookup**: 키 ID 및 속성 기반 암호화 키 검색 연산 (`crypto_key_search.cpp`).
  * **Key Extraction & Raw Retrieval**: 키 데이터 및 parameter 추출 바이트 연산 (`crypto_key_extract.cpp`, `crypto_key_get_key.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Key Search & Object Management (`crypto_key_search.cpp`, `crypto_key_object.cpp`)**:
  * Key ID / Attribute 기반 in-memory key 검색 연산.
  * 키 객체 pointer 및 indexing 기반 key lifecycle 관리.
* **Key Extract & Raw Data Handling (`crypto_key_extract.cpp`, `crypto_key_get_key.cpp`)**:
  * 바이트 buffer 대상 원시 키(Raw key) 추출 및 export 연산.

---

### 3. 핵심 동작 mechanism

* **Key Search & Extraction Flow (`crypto_key_search.cpp`, `crypto_key_extract.cpp`)**:
  * 키 조회 요청 수신 -> `crypto_key_search` 키 ID lookup -> `crypto_key_object` 유효성 및 validation 검증 -> `crypto_key_extract` 바이트 buffer 추출 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-KEY-01** | `crypto_key_extract.cpp` 내 extract 연산 시 memory boundary check 및 buffer overflow 예외 처리 보완 | High | 미진행 |
| **TODO-KEY-02** | `crypto_key_search.cpp` 내 invalid key ID/attribute 조회 시 null pointer 예외 처리 검증 | High | 미진행 |
| **TODO-KEY-03** | `crypto_key_object.cpp` 내 raw pointer 참조 시 memory leak 및 dangling pointer 예외 처리 확인 | High | 미진행 |
| **TODO-KEY-04** | `crypto_key_get_key.cpp` 내 raw key data export 시 sensitive data masking 및 secure memory wipe 적용 검토 | Medium | 미진행 |
| **TODO-KEY-05** | `crypto_key.cpp` 내 key format validation 연산 강화 | Low | 미진행 |
