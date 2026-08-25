## [C++11] Base16 encoding/decoding module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 4648 규격을 준수하는 Base16(Hex) encoding, decoding 및 RFC pattern 처리 module.
* **주요 기능**:
  * **high-level interface**: `std::string`, `binary_t`, `basic_stream` 등 다양한 container간 변환 지원.
  * **low-level 성능 최적화**: `snprintf` 대신 bit shift 연산 및 lookup table 기반 직접 변환 방식 적용 (`conv_fast`, `hex_digits`).
  * **RFC 다양한 pattern 지원 (`base16_encode_rfc`, `base16_decode_rfc`)**:
    * RFC 7516 style의 배열 형태 `[227, 197, 117, ...]` 10진수 리터럴 parsing.
    * RFC 7539 style의 `00:01:02:...` 구분자 포함 Hex pattern 및 공백/줄바꿈 포함 포맷 처리.
  * **홀수 길이 Hex decoding 지원**: NIST CAVP test vector 지원을 위한 홀수(odd size) 길이 decoding 지원.
  * **`0x` 접두사 자동 스킵**: decoding 시 "0x" 접두사 자동 감지 및 건너뛰기.
* **C++11 특징**:
  * `custom::encoder_stream_traits` 및 SFINAE (`std::enable_if`) 기반 메모리 2단계 확보(Reserve-Commit) template 처리.
  * Move semantics (`std::move`)를 통한 임시 객체 반환 최적화.

---

### 2. 주요 API 및 계층 구조

**High-Level API (`hotplace` namespace)**

* `base16_encode(...)`: 다양한 입력을 Hex 문자열 또는 container로 encoding.
* `base16_decode(...)`: Hex 문자열을 `binary_t` 또는 지정 container로 decoding.
* `base16_encode_rfc(...)` / `base16_decode_rfc(...)`: 10진수 배열, 콜론/공백 구분 포맷 대응 API.
* `base16_compare(...)`: 앞자리 '0' (Leading Zero) 제거 후 의미적 바이트 동등성 비교.

**Low-Level C-Style API (`hotplace::lowlevel` namespace)**

```cpp
namespace hotplace {
namespace lowlevel {

// buffer 크기 산출 및 1차/2차 메모리 복사 방식
return_t base16_encode(const byte_t* source, size_t size, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_decode(const char* source, size_t size, byte_t* buf, size_t* buflen);

}  // namespace lowlevel
}  // namespace hotplace
```
[cite: 55, 56]

---

### 3. 핵심 동작 mechanism

* **2단계 buffer 할당 (Reserve & Commit pattern)**:
  * 1차 호출: `buf`를 `nullptr`로 설정하여 필요한 buffer 크기(`size_reserve`) 산출 후 `errorcode_t::insufficient_buffer` 반환[cite: 53, 55].
  * 2차 호출: `traits::reserve`로 메모리 확보 후 실제 encoding/decoding 실행 및 `traits::commit`으로 바이트 크기 확정[cite: 53].
* **flag option (`flags`)**:
  * `encoding_flag_t::encoding_base16_capital`: 대문자 Hex 사용 ("0123456789ABCDEF")[cite: 55].
  * `encoding_flag_t::encoding_base16_space`: 바이트 간 공백(' ') 구분자 추가[cite: 55].
  * `encoding_notrunc`: 기존 출력 buffer Truncate 생략 후 이어 쓰기[cite: 53].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **#1** | `base16_decode_rfc`의 10진수 배열 parsing 시 `atoi` 대신 안전한 정수 변환 함수로 대체 | High | 미진행 |
| **#2** | `base16_encode_rfc`에서 콜론(`:`) 구분 포맷 생성 option flag 추가 | Medium | 미진행 |
| **#3** | SIMD/AVX2 명령어셋을 활용한 Low-level encoding/decoding loop 성능 개선 검토 | Low | 미진행 |
