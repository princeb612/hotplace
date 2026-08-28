# Huffman Coding (`huffman_coding`) - published by Gemini

## 1. Overview & Key Features

The `huffman_coding` module is a C++11 Huffman Encoding/Decoding processing module designed to support general data compression/restoration and HTTP/2 HPACK (RFC 7541) header compression mechanisms.

* **Dynamic Learning & Inference (Learn/Infer)**: Dynamic Huffman Tree and code generation by tracking symbol byte frequencies within the input stream.
* **Pre-Defined Table Loading (Imports)**: Flexible loading of pre-defined Huffman Code tables, including the RFC 7541 static table standard.
* **Bit-Level Encoding/Decoding**: High-speed bitstream processing leveraging a dedicated encoding cache array (`_encode_cache`) combined with a prefix search trie structure (`_trie`).
* **C++11 Metaprogramming Optimization**: Applies SFINAE template control via `std::enable_if`, lambda expressions, and Fluent Interface patterns.

---

## 2. Key Implementation Areas & Technical Elements

* **Fast Lookup Encoding Cache**: Pre-calculates bit codes (`bit_code`) and bit lengths (`bit_len`) for encoding target symbols (0–256) into a 256-entry cache table (`_encode_cache`) to significantly boost lookup speeds.
* **Trie-based Prefix Scan Decoding**: Converts incoming byte streams sequentially into bit characters while performing prefix matching through the `t_trie<char>` trie data structure for rapid restoration to original symbols.
* **RFC 7541 EOS Padding Enforcement**: Strictly enforces padding logic that fills residual bit space with MSB '1' bits upon encoding completion, aligning with specifications defining minimum code length as 5 bits or more.
* **Expected Size Calculator**: Provides an `expect()` API to scan original input data prior to stream encoding to predict final compressed byte sizes in advance.

---

## 3. Major Data Structures, Classes & API Reference

### `huffman_coding` Class Declaration

```cpp
namespace hotplace {

class huffman_coding {
   public:
    typedef hc_code hc_code_t;

    huffman_coding();
    ~huffman_coding();

    void reset();

    // Dynamic frequency-based huffman code generation (Fluent Interface)
    huffman_coding& operator<<(const char* s);
    huffman_coding& load(const char* s);
    huffman_coding& learn();
    huffman_coding& infer();

    // Pre-defined table loading
    huffman_coding& imports(const hc_code_t* table);
    huffman_coding& imports(const std::map<uint8, std::string>& m);

    // Expected compressed size calculation (in Bytes)
    return_t expect(const byte_t* source, size_t size, size_t& size_expected) const;

    // Encoding / decoding template methods
    template <typename T, ...>
    return_t encode(T& streambuf, const byte_t* source, size_t size, bool usepad = true) const;

    template <typename T, ...>
    return_t decode(T& streambuf, const byte_t* source, size_t size, uint32 flags = 0) const;

   private:
    struct encode_cache_t {
        uint32 bit_code;
        uint8 bit_len;
    };

    measure_tree_t _measure;     // Symbol frequency measurement
    btree_t _btree;               // Weight-based tree merging
    codetable_t _codetable;       // Sym -> Bit String mapping
    t_trie<char> _trie;           // Prefix Scan Trie for decoding
    encode_cache_t _encode_cache[256 + 1]; // Encoding speedup cache
};

}  // namespace hotplace
```
[cite: 15]

---

## 4. Operational Principles[cite: 15]

1. **Dynamic Learning & Encoding Process (`learn` / `encode`)**:
   * Parses input text to record symbol frequencies in `_measure`, merging weight-based trees to construct `btree_t` and `_codetable`[cite: 15].
   * Upon calling `encode`, references the `_encode_cache` array to perform bitwise operations and bit-packs into 8-bit (1-byte) units before pushing to the output stream buffer[cite: 15].
2. **Trie-Based Decoding Process (`decode`)**:
   * Accumulates incoming byte streams into a bit-level queue (`que`)[cite: 15].
   * Continuously emits matched original symbols using `_trie.scan`, a trie data structure optimized for prefix scanning[cite: 15].
3. **Termination Padding Control**:
   * Applies RFC 7541 padding bit rules based on the `usepad` option for trailing unaligned bits during encoding finalization[cite: 15].

---

## 5. Usage Example (C++11 Standard)[cite: 15]

```cpp
#include <iostream>
#include <hotplace/sdk/base/basic/huffman_coding.hpp>

int main() {
    using namespace hotplace;

    huffman_coding hc;

    // 1. Train frequency and infer codes from input string (Fluent Interface)
    std::string sample_data = "hello hotplace huffman stream";
    hc << sample_data.c_str();
    hc.learn().infer();

    // 2. Perform compression (encode)
    basic_stream encoded_stream;
    hc.encode(encoded_stream, (const byte_t*)sample_data.data(), sample_data.size());

    // 3. Perform restoration (decode)
    basic_stream decoded_stream;
    hc.decode(decoded_stream, (const byte_t*)encoded_stream.data(), encoded_stream.size());

    std::string result((const char*)decoded_stream.data(), decoded_stream.size());
    std::cout << "Decoded Result: " << result << std::endl;

    return 0;
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-HC-01** | `HIGH` | **Optimize Bit Packing Buffering via Bit Shift**<br><br>- Refactor 1-bit transfer logic inside `encode` loop to bit shift-based buffering for performance improvement | `Postponed` | Not started |
| **TODO-HC-02** | `HIGH` | **Refactor Decoding Queue to Integer Bit Buffer**<br><br>- Convert `std::string que` bit queue in `decoding` process to integer bit buffer mechanism | `Postponed` | Not started |
| **TODO-HC-03** | `MEDIUM` | **Add RFC 7541 Static Code Large Stream Tests**<br><br>- Expand unit test cases for large streams using RFC 7541 Appendix B static Huffman Code table | `In Progress` | In progress |
| **TODO-HC-04** | `LOW` | **Review C++11 `constexpr` Compile-Time Encoding Table Generation**<br><br>- Investigate compile-time constant creation of Huffman encoding tables using `constexpr` | `Postponed` | Not started |

---
