## decoder stream module (`decoder_stream.cpp` / `decoder_stream.hpp`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: chunk(Chunk) 단위로 입력되는 encoding 데이터(Base16, Base64, Base64URL, HTTP/2 Huffman Coding)를 누적 및 decoding하여 binary 데이터(`binary_t`)로 복원하는 stream class.
* **주요 기능**:
  * **chunk 스트리밍 decoding**: encoding 단위(Base16: 2자, Base64: 4자)에 맞춰 끊어지지 않은 잔여 데이터를 내부 buffer(`_encbuf`)에 저장하여 stream의 연속성을 보장.
  * **HTTP/2 huffman decoding 지원**: 비트 단위 huffman coding 잔여 비트(`_huffbuf`)를 관리하며 EOS padding의 유효성을 검증.
  * **stream 연산자 overloading**: `operator<<`, `operator+=`, `add()` 등 template 완벽 전달(Perfect Forwarding) 및 method chaining 지원.
* **C++11 특징**: Move Semantics, perfect forwarding (`std::forward`), default move/copy 생성자 활용.

---

### 2. 주요 class 및 데이터 구조

```cpp
namespace hotplace {

class decoder_stream {
   public:
    decoder_stream(encoding_t enc);

    // 복사 및 이동 생성자/대입 연산자 (C++11 default)
    decoder_stream(const decoder_stream& other) = default;
    decoder_stream(decoder_stream&& other) = default;
    decoder_stream& operator=(const decoder_stream& other) = default;
    decoder_stream& operator=(decoder_stream&& other) = default;

    decoder_stream& set_maxsize(size_t size);
    size_t get_maxsize() const;
    encoding_t get_encoding() const;

    // 최종 복원된 binary 데이터 추출 (내부적으로 flush 호출)
    binary_t data();

    // 입력 쓰기 interface
    return_t write(const char* data, size_t size);
    return_t write(const byte_t* data, size_t size);

    decoder_stream& add(const char* data, size_t size);
    decoder_stream& add(const byte_t* data, size_t size);

    template <typename T>
    decoder_stream& add(T&& value);

    template <typename T>
    decoder_stream& operator+=(T&& value);

    decoder_stream& operator<<(const char* value);
    decoder_stream& operator<<(const std::string& value);
    decoder_stream& operator<<(const basic_stream& value);

   protected:
    return_t flush();

   private:
    struct encbuf_t {  // chunk 경계 미달 데이터 보관 buffer
        char buf[5];
        uint8 len;     // [0..4]
        uint8 unitsize(encoding_t encoding);
        uint8 free_space(encoding_t encoding);
        void reset();
    };

    encoding_t _encoding;
    size_t _maxsize;
    binary_t _buffer;       // decoding 완료된 binary 결과 저장소
    encbuf_t _encbuf;       // Base16(2바이트), Base64(4바이트) 임시 buffer
    std::string _huffbuf;   // huffman 코딩용 비트 buffer
};

}  // namespace hotplace
```
[cite: 50, 51]

---

### 3. 핵심 동작 mechanism

* **경계 처리 및 분할 decoding (`write`)**:
  * **Base16 / Base64**: 입력 단위(`unitsize`: Base16=2, Base64=4) 미만으로 남은 자릿수를 `_encbuf`에 보관[cite: 50, 51]. 다음 `write` 호출 시 `free_space()`만큼 채워 완전히 구성되면 decoding을 수행하고, 나머지는 몫과 여분으로 나눠 연속 decoding[cite: 50].
  * **HTTP/2 Huffman**: `http_huffman_coding` singleton을 호출하여 stream decoding 수행[cite: 50].
* **stream 종단 검증 (`flush`)**:
  * `data()` 호출 시 남은 데이터 정리를 위해 자동 실행[cite: 50].
  * Base16/Base64 잔여 유효 데이터 decoding 처리[cite: 50].
  * **huffman coding padding 검증**: padding 비트(`_huffbuf`)가 8비트 이상이거나 모두 '1'(EOS 비트 규격)로 채워지지 않은 경우 `errorcode_t::bad_data` 반환[cite: 50].
---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **TODO-DECODER-01** | `encoding_base16rfc` 미지원 decoding logic의 구현 및 pipeline 추가 | High | 미진행 |
| **TODO-DECODER-02** | `flush()` 내 Base64 잔여 1바이트 오입력 시 오류 code 명시적 세분화 | Medium | 진행 중 |
| **TODO-DECODER-03** | `_maxsize` 초과 시 기존 stream buffer의 rollback 및 안전 처리 검증 | Medium | 미진행 |
| **TODO-DECODER-04** | C++11 Move assignment 수행 시 내부 buffer 상태 초기화 안전성 강화를 위한 단위 테스트 추가 | Low | 미진행 |
