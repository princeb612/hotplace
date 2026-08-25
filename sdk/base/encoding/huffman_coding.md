## huffman coding module (`huffman_coding`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 데이터 압축 및 복원, HPACK(RFC 7541) 기반 HTTP/2 header 압축용 huffman encoding/decoding 처리 module.
* **주요 기능**:
  * **자동 학습 (Learn/Infer)**: stream 내 바이트 빈도수를 측정하여 huffman tree를 동적으로 생성 및 code 생성.
  * **사전 정의 code loading (Imports)**: RFC 7541 표준 등의 고정 huffman table 지원.
  * **비트 단위 encoding/decoding**: 캐시 구조체(`_encode_cache`) 및 트라이(`t_trie`) 구조를 활용한 비트 stream 처리.
* **C++11 특징**: `std::enable_if` 기반 template metaprogramming(SFINAE), lambda 함수 사용.

---

### 2. 주요 class 구성 및 데이터 구조

```cpp
namespace hotplace {

class huffman_coding {
   public:
    typedef hc_code hc_code_t;

    huffman_coding();
    ~huffman_coding();

    void reset();

    // 동적 빈도 기반 huffman code 생성 (Fluent Interface)
    huffman_coding& operator<<(const char* s);
    huffman_coding& load(const char* s);
    huffman_coding& learn();
    huffman_coding& infer();

    // 사전 정의 table loading
    huffman_coding& imports(const hc_code_t* table);
    huffman_coding& imports(const std::map<uint8, std::string>& m);

    // 예상 압축 크기 계산 (Byte 단위)
    return_t expect(const byte_t* source, size_t size, size_t& size_expected) const;

    // encoding / decoding template method
    template <typename T, ...>
    return_t encode(T& streambuf, const byte_t* source, size_t size, bool usepad = true) const;

    template <typename T, ...>
    return_t decode(T& streambuf, const byte_t* source, size_t size, uint32 flags = 0) const;

   private:
    struct encode_cache_t {
        uint32 bit_code;
        uint8 bit_len;
    };

    measure_tree_t _measure;     // 심볼별 빈도수 측정
    btree_t _btree;               // 가중치 기준 트리 병합
    codetable_t _codetable;       // Sym -> Bit String mapping
    t_trie<char> _trie;           // decoding용 Prefix Scan Trie
    encode_cache_t _encode_cache[256 + 1]; // encoding 고속화 캐시
};

}  // namespace hotplace
```

---

### 3. 핵심 동작 mechanism

* **encoding 처리 (`encode`)**:
  * `_encode_cache` 배열을 참조하여 `sym`에 대응하는 `bit_code`와 `bit_len`을 획득.
  * 비트 연산을 통해 8비트(1 바이트) 단위로 packing 후 stream buffer에 push.
  * EOS padding 처리: 최소 code 길이가 5비트 이상인 경우 RFC 7541 표준 규격(MSB 1 채움)에 맞춰 padding 적용.
* **decoding 처리 (`decode` / `decoding`)**:
  * 바이트 stream을 비트 문자열(`'0'`, `'1'`) 형태로 전환하며 queue(`que`)에 축적.
  * Prefix 탐색에 최적화된 트라이 자료구조(`_trie.scan`)를 이용해 matching되는 심볼을 직렬 추출.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `encode` loop 내 1비트 단위 전송을 bit shift 기반 buffer링으로 최적화 (성능 개선) | High | 미진행 |
| **#2** | `decoding` 과정의 `std::string que` 문자열 기반 비트 queue를 정수형 비트 buffer 방식으로 refactoring | High | 미진행 |
| **#3** | RFC 7541 Appendix B 정적 huffman code에 대한 대용량 stream 단위 테스트 추가 | Medium | 진행 중 |
| **#4** | C++11 `constexpr` 활용 가능한 encoding table compile-time 생성 검토 | Low | 미진행 |
