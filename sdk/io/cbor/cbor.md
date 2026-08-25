## CBOR (Concise Binary Object Representation) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 8949 (CBOR) 표준 binary 데이터 포맷을 생성, encoding, decoding, parsing 처리하는 C++11 library module.
* **주요 기능**:
  * **객체 모델 기반 설계**: `cbor_object` 상속 구조로 기본 타입(정수, `cbor_data`), 문자열/바이트열(`cbor_tstrings`, `cbor_bstrings`), 복합 타입(`cbor_array`, `cbor_map`, `cbor_pair`), tag/간단한 값(`cbor_simple`) 구현.
  * **encoding & decoding**: `cbor_encode`를 통한 stream binary 직렬화 및 `cbor_reader`를 통한 buffer stream decoding/parsing.
  * **debugging 및 전송 구조**: `cbor_visitor`를 통한 AST 순회/dump 및 `cbor_publisher` pattern 지원.
* **C++11 특징**:
  * smart pointer(`std::shared_ptr`, `std::unique_ptr`) 대신 reference counting(`addref`/`release`) style 기반 메모리 제어.
  * `std::vector<uint8_t>`, `std::string` 및 표준 STL container 중심의 C++11 데이터 이동과 lambda 활용.

---

### 2. 주요 class 및 API 구조

**CBOR 객체 및 팩토리 구조 (`cbor_object`)**

```cpp
namespace hotplace {

// 최상위 추상 데이터 객체
class cbor_object {
   public:
    virtual cbor_type_t type() const = 0;
    virtual int addref();
    virtual int release();
};

// CBOR encoder 및 decoder
class cbor_encode {
   public:
    cbor_encode& encode(const cbor_object* object, binary_t& stream);
};

class cbor_reader {
   public:
    int parse(const uint8_t* buffer, size_t size, cbor_object** out);
};

}  // namespace hotplace

```

---

### 3. 핵심 동작 mechanism

* **주요 타입별 class**:
  * `cbor_data`: 정수형(Unsigned/Negative Integer) 및 floating point 데이터 표현.
  * `cbor_bstrings` / `cbor_tstrings`: binary byte string 및 UTF-8 text string 데이터 관리.
  * `cbor_array` / `cbor_map`: 요소를 순차 또는 Key-Value 쌍으로 보관하는 container 객체.
  * `cbor_simple`: CBOR Simple Value(true/false/null/undefined) 및 Tagged 타입 처리.
* **encoding & decoding mechanism**:
  * `cbor_encode`: CBOR Major Type Header(3비트 Major Type + 5비트 Additional Info)를 비트 연산으로 조립 후 데이터 payload를 `binary_t` stream에 연속 작성.
  * `cbor_reader`: binary stream의 첫 바이트(Major Type)를 해석하여 해당 객체 타입(`cbor_object` 파생 class)으로 복원 및 트리 구조 형성.

---

### 4. TODO list

### CBOR module 전용 TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `cbor_reader::parse` 중 부정형(Indefinite Length) binary/text stream parsing 경계 검증 정밀화 | High | 미진행 |
| **#2** | `cbor_object` 계열의 수동 reference counting(`addref`/`release`) 구조를 `std::shared_ptr` 기반 표준 C++11 모델로 refactoring 검토 | Medium | 미진행 |
| **#3** | `cbor_encode` 성능 최적화를 위한 임시 buffer 재할당 최소화 및 메모리 풀링 적용 | Low | 미진행 |
