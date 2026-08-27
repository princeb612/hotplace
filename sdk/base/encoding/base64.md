## Base64 / Base64URL encoding 및 decoding module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 4648 표준 및 RFC 7515(JWS Appendix C) 규격을 준수하는 Base64 및 Base64URL encoding/decoding module.
* **주요 기능**:
  * **표준 및 URL-Safe 규격 동시 지원**: `encoding_base64`(`+`, `/`, `=` padding) 및 `encoding_base64url`(`-`, `_`, padding 없음) 모드 선택 지원.
  * **비트 비트field 공통체(`union`) 기반 비트 변환**: 3바이트(24비트) 데이터를 6비트 4개(`e1`, `e2`, `e3`, `e4`)로 비트 field mapping하여 직관적이고 빠르게 encoding 처리.
  * **문자열 복원 전용 interface**: decoding 결과가 text인 경우 `std::string` 형태로 직접 반환하는 `base64_decode_careful` 제공.
* **C++11 특징**:
  * `custom::encoder_stream_traits` 및 SFINAE (`std::enable_if`) 기반 메모리 2단계 확보(Reserve-Commit) template 처리.
  * `std::string::data()` overloading 호출 및 Move Semantics 최적화.

---

### 2. 주요 class 및 API 구조

**High-Level API (`hotplace` namespace)**

* `base64_encode(...)`: `const char*`, `const byte_t*`, `std::string`, `binary_t`, `basic_stream` 등 다양한 입력형 overloading 제공.
* `base64_decode(...)`: 입력 데이터를 decoding하여 `binary_t` 또는 template stream buffer에 저장.
* `base64_decode_careful(...)`: 원본 소스가 text 문자열일 때 `std::string` 타입으로 안전하게 반환받는 전용 interface.

**Low-Level C-Style API (`hotplace::lowlevel` namespace)**

```cpp
namespace hotplace {
namespace lowlevel {

// 2단계 buffer 메모리 할당 방식을 사용하는 low-level 연산 함수
return_t base64_encode(const byte_t* source, size_t source_size, char* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_decode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);

}  // namespace lowlevel
}  // namespace hotplace
```
[cite: 59, 60]

---

### 3. 핵심 동작 mechanism

* **비트변환 공통체 (`base64_conv_t`)**:
  ```cpp
  typedef union {
      struct {
          unsigned char c1, c2, c3; // 8-bit * 3
      };
      struct {
          unsigned int e1 : 6, e2 : 6, e3 : 6, e4 : 6; // 6-bit * 4
      };
      uint32 i32;
  } base64_conv_t;
  ``` [cite: 59]
* **Reserve & Commit pattern (2단계 메모리 할당)**:
  * 1차 호출: `buffer`에 `nullptr` 전달 시 decoding/encoding에 필요한 buffer 크기(`size_need`) 계산 후 `errorcode_t::insufficient_buffer` 반환[cite: 58, 59].
  * 2차 호출: 계산된 크기만큼 `traits::reserve` 수행 후 decoding/encoding 실행, 완료 시 `traits::commit`으로 실제 기록 크기 확정[cite: 58].
* **Base64URL padding 및 알파벳 변환**:
  * `encoding_base64`: 62번째/63번째 문자로 `+`, `/` 사용하며 3바이트 경계 미달 시 `=` padding 부가[cite: 59].
  * `encoding_base64url`: `-`, `_` 문자를 사용하며, RFC 7515 Appendix C 규격에 따라 padding 문자를 생성하지 않고 길이를 단축 계산하여 종료[cite: 58, 59].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **TODO-BASE64-01** | `base64_decode` loop 시 유효하지 않은 Base64 문자에 대한 검증 및 오류 처리 강화 | High | 미진행 |
| **TODO-BASE64-02** | Base64URL decoding 시 입력 끝부분 padding(`=`) 생략 건에 대한 완충 정밀 검증 logic 작성 | Medium | 미진행 |
| **TODO-BASE64-03** | SIMD/AVX2 적용을 통한 대용량 binary_t Base64 encoding/decoding loop 성능 향상 검토 | Low | 미진행 |
