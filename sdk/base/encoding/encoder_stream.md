## encoding stream module (`encoder_stream`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 다양한 encoding algorithm(Base16, Base64, Base64URL, HTTP/2 Huffman Coding)을 stream 방식으로 데이터 encoding을 수행하는 module.
* **주요 기능**:
  * **멀티 encoding 지원**: Base16 (표준/RFC), Base64 (표준/URL), HTTP/2 Huffman Coding 지원.
  * **스트리밍 분할 데이터 처리**: `encbuf_t`(3바이트 경계) 및 `bitbuf_t`(비트 단위) 내부 buffer를 사용하여 chunk(Chunk) 단위 입력을 매끄럽게 처리.
  * **Type Traits 기반 자동 변환**: SFINAE 및 C++11 `is_integral` 연산자 overloading을 이용해 정수형(Big/Little Endian 변환 포함), 문자열, binary_t 스트리밍 지원.
* **C++11 특징**: SFINAE (`std::enable_if`), Type Traits (`encoder_stream_traits`), Perfect Forwarding (`std::forward`), Move Semantics 활용.

---

### 2. 주요 class 및 데이터 구조

```cpp
namespace hotplace {

class encoder_stream {
   public:
    encoder_stream(encoding_t enc, bool use_bigendian = true);

    // buffer 설정 및 관리
    encoder_stream& set_maxsize(size_t size);
    size_t get_maxsize() const;
    encoding_t get_encoding() const;
    encoder_stream& set_endian(bool use_bigendian);
    bool is_bigendian() const;

    encoder_stream& clear();
    std::string str();   // flush() 후 std::string 결과 반환
    binary_t bin();      // flush() 후 binary_t 결과 반환

    // 데이터 쓰기 interface
    return_t write(const byte_t* data, size_t size);

    template <typename T>
    encoder_stream& add(T&& value);

    template <typename T>
    encoder_stream& operator+=(T&& value);

    // 정수형 타입 stream 연산자 (Endianness 변환 적용)
    template <typename T, typename std::enable_if<custom::is_integral<T>::value && !std::is_same<T, bool>::value, int>::type = 0>
    encoder_stream& operator<<(T value);

    // 기타 타입 연산자 overloading
    encoder_stream& operator<<(bool value);
    encoder_stream& operator<<(const char* value);
    encoder_stream& operator<<(const std::string& value);
    encoder_stream& operator<<(const binary_t& value);
    encoder_stream& operator<<(const basic_stream& value);

   protected:
    return_t flush(); // 남은 내부 buffer padding 및 최종 처리

   private:
    struct encbuf_t {  // Base64 3-byte 단위 처리 buffer
        byte_t buf[3];
        uint8 len;
        uint8 unitsize(encoding_t encoding);
        uint8 free_space(encoding_t encoding);
        void reset();
    };

    struct bitbuf_t {  // Huffman coding 비트 단위 처리 buffer
        uint8 buf;
        uint8 len;
        void reset();
    };

    encoding_t _encoding;
    bool _use_bigendian;
    size_t _maxsize;
    std::string _buffer;
    binary_t _bin;
    encbuf_t _encbuf;
    bitbuf_t _bitbuf;
};

}  // namespace hotplace
```
[cite: 49, 50]

---

### 3. 핵심 동작 mechanism

* **chunk 단위 데이터 연산 (`write`)**:
  * **Base16**: 입력 block을 즉시 Hex 문자열로 변환하여 출력 buffer에 누적[cite: 49].
  * **Base64 / Base64URL**: 입력 데이터를 3바이트 `unitsize` 경계로 분할 처리[cite: 49]. 미달하는 잔여 데이터는 내부 `_encbuf`에 유지하고, 다음 `write` 호출 시 병합하여 encoding 수행[cite: 49].
  * **HTTP/2 Huffman (`encoding_h2hcodes`)**: `http_huffman_coding` 싱글톤 pattern을 활용[cite: 49]. 비트 단위 연산으로 `_bitbuf`에 저장 후 8비트(1바이트)가 채워지면 `_bin`에 packing[cite: 49].
* **stream 종료 처리 (`flush`)**:
  * stream이 닫히거나 출력(`str()`, `bin()`)이 요청될 때 `flush()` 호출[cite: 49].
  * Base64 잔여 데이터 padding 처리 및 Huffman 비트 buffer Shift/Padding 후 데이터 마무리[cite: 49].
* **타입 특성화 기법 (`encoder_stream_traits`)**:
  * `std::string` 및 `binary_t` container에 대해 메모리 pre-allocation 및 direct writing interface 제공[cite: 51].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **#1** | Base128(LEB128/VLQ) encoding module의 `encoder_stream` pipeline 통합 | High | 미진행 |
| **#2** | `_maxsize` 초과 시 예외 처리 logic 안전성 강화 및 커스텀 allocator 연동 | Medium | 진행 중 |
| **#3** | C++11 `std::is_constructible` 활용을 통한 `operator<<` template 지원 확장 | Medium | 미진행 |
| **#4** | Zlib/Deflate 등 압축 algorithm stream encoder 확장 구조 검토 | Low | 미진행 |
