## CBOR (Concise Binary Object Representation) - published by Gemini

### 1. 개요 및 주요 특징

* **module 역할**: RFC 8949 (구 RFC 7049) 표준 규격을 준수하여 binary 기반 데이터 구조를 encoding, decoding, parsing 처리하는 C++11 library module.
* **주요 기능**:
  * **표준 test vector 검증**: `testcase_rfc7049.cpp`, `testvector_cbor.cpp`, `testvector_cbor.yml` 기반의 RFC 공식 검증 테스터 구성.
  * **객체 모델 기반 설계**: `cbor_object` 상속 구조로 정수/데이터(`cbor_data`), 문자열/바이트열(`cbor_tstrings`, `cbor_bstrings`), 배열/맵(`cbor_array`, `cbor_map`), tag/간단한 값(`cbor_simple`) 표현.
  * **직렬화 및 binary decoding**: `cbor_encode`를 통한 stream binary 생성 및 `cbor_reader` 기반의 parsing/객체 트리 복원.
  * **방문자 pattern & 전송 구조**: `cbor_visitor`를 통한 AST 순회/dump 기능 및 `cbor_publisher` pattern 지원.
* **C++11 특징**:
  * reference counting(`addref`/`release`) style 방식의 resource 제어 및 메모리 life-cycle 관리.
  * `std::vector<uint8_t>`, `std::string` 및 C++11 STL mechanism 중심의 데이터 이동 연산.

---

### 2. 주요 class 및 API 구조

**CBOR core 객체 및 검증 테스터**

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

* **주요 타입별 class 구조**:
  * `cbor_data`: Unsigned/Negative Integer 및 Floating-point 수치 데이터 표현.
  * `cbor_bstrings` / `cbor_tstrings`: Byte String 및 UTF-8 Text String binary 제어.
  * `cbor_array` / `cbor_map`: 요소의 순차열 및 Key-Value mapping 객체 관리.
  * `cbor_simple`: Simple Value(true/false/null/undefined) 및 Tagged 데이터 처리.
* **RFC 8949 / RFC 7049 표준 검증 mechanism**:
  * `testvector_cbor.yml` 및 `testcase_rfc7049.cpp`에 명시된 RFC 표준 test vector 집합을 parsing하여, binary encoding/decoding 결과가 규격과 완벽히 일치하는지 자동 검증.
* **encoding & decoding 연산**:
  * `cbor_encode`: Major Type Header(3비트 Major Type + 5비트 Additional Info) 조합 후 데이터 payload를 `binary_t` stream에 순차 기록.
  * `cbor_reader`: binary stream의 header 영역을 해석하여 대응되는 `cbor_object` 파생 개체를 동적 생성 및 트리를 복원.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `cbor_reader::parse` 중 부정형(Indefinite Length) binary/text stream parsing 경계 검증 정밀화 | High | 미진행 |
| **#2** | `cbor_object` 계열의 수동 reference counting(`addref`/`release`) 구조를 `std::shared_ptr` 기반 표준 C++11 모델로 refactoring 검토 | Medium | 미진행 |
| **#3** | `cbor_encode` 성능 최적화를 위한 임시 buffer 재할당 최소화 및 메모리 풀링 적용 | Low | 미진행 |
| **#4** | `testvector_cbor.yml`에 최신 RFC 8949 추가 Edge Case test vector 확장 및 debug 출력 logic 개선 | Low | 미진행 |
