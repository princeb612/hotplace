# Decoder Stream (`decoder_stream`) - published by Gemini

## 1. Overview & Key Features

The `decoder_stream` module is a C++11 pipeline stream module that receives encoded data (Base16, Base64, Base64URL, HTTP/2 Huffman Coding) input on a chunk-by-chunk basis, accumulates and decodes it, and restores it into final binary data (`binary_t`).

* **Chunk Streaming Decoding**: Ensures stream continuity by maintaining unaligned residual data below standard decoding units (Base16: 2 chars, Base64: 4 chars) inside an internal buffer (`_encbuf`).
* **HTTP/2 Huffman Decoding & Padding Validation**: Precisely manages bit-level Huffman coding residual bits (`_huffbuf`) and strictly validates EOS padding specifications and bit validity upon stream termination.
* **Chaining Operator Overloading**: Provides template Perfect Forwarding and method chaining interfaces including `operator<<`, `operator+=`, and `add()`.
* **C++11 Metaprogramming Optimization**: Leverages Move Semantics, Perfect Forwarding (`std::forward`), and default copy/move constructors and assignment operators to improve memory transfer efficiency.

---

## 2. Key Implementation Areas & Technical Elements

* **Unaligned Chunk Boundary Buffer**: Temporarily stores truncated inputs below 2 characters (Base16) or 4 characters (Base64) inside `_encbuf` and merges them with subsequent input chunks to resume normal decoding.
* **HTTP/2 EOS Bit-Padding Compliance**: Validates that all residual bit padding consists of '1's per HTTP/2 RFC 7540 rules, detecting unaligned padding bits of 8 bits or greater or corrupted EOS bits to safeguard data integrity.
* **Two-Phase Flush Finalization**: Triggers a final `flush()` upon `data()` invocation to perform ultimate validity checks on accumulated buffers and return precise error codes.
* **Zero-Copy Stream Trait Integration**: Adopts C++11 default move semantics to prevent redundant deep buffer copies when transferring or passing stream instances.

---

## 3. Major Data Structures, Classes & API Reference

### `decoder_stream` Class Declaration

```cpp
namespace hotplace {

class decoder_stream {
   public:
    decoder_stream(encoding_t enc);

    // Copy and move constructors / assignment operators (C++11 default)
    decoder_stream(const decoder_stream& other) = default;
    decoder_stream(decoder_stream&& other) = default;
    decoder_stream& operator=(const decoder_stream& other) = default;
    decoder_stream& operator=(decoder_stream&& other) = default;

    decoder_stream& set_maxsize(size_t size);
    size_t get_maxsize() const;
    encoding_t get_encoding() const;

    // Extracts final restored binary data (invokes flush() internally)
    binary_t data();

    // Input writing interfaces
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
    struct encbuf_t {  // Buffer for holding unaligned chunk boundary data
        char buf[5];
        uint8 len;     // [0..4]
        uint8 unitsize(encoding_t encoding);
        uint8 free_space(encoding_t encoding);
        void reset();
    };

    encoding_t _encoding;
    size_t _maxsize;
    binary_t _buffer;       // Decoded binary output storage
    encbuf_t _encbuf;       // Base16 (2 bytes), Base64 (4 bytes) temporary buffer
    std::string _huffbuf;   // Bit buffer for Huffman coding
};

}  // namespace hotplace
```
[cite: 13]

---

## 4. Operational Principles[cite: 13]
1. **Boundary Handling & Split Decoding (`write`)**:
   * **Base16 / Base64**: Holds digits below the required `unitsize` (Base16=2, Base64=4) inside `_encbuf`[cite: 13]. Upon subsequent `write` calls, completes a block by filling up to `free_space()` to decode, and continuously decodes the remaining data in unit splits[cite: 13].
   * **HTTP/2 Huffman**: Invokes the `http_huffman_coding` singleton to perform bit-sequence parsing and decoding consecutively[cite: 13].
2. **Stream Termination Handling (`flush`)**:
   * Automatically executes `flush()` when `data()` is invoked to finalize residual data[cite: 13].
   * Decodes remaining Base16/Base64 data blocks[cite: 13].
   * **Huffman Coding Padding Validation**: Returns `errorcode_t::bad_data` upon detecting integrity errors where residual padding bits (`_huffbuf`) exceed 8 bits or are not filled entirely with '1's (EOS bit specification)[cite: 13].
3. **Memory Boundary Protection**:
   * Preemptively blocks encoded inputs exceeding limits when `_maxsize` is configured, preventing buffer overflows[cite: 13].

---

## 5. Usage Example (C++11 Standard)[cite: 13]

```cpp
#include <iostream>
#include <hotplace/sdk/base/basic/decoder_stream.hpp>

int main() {
    using namespace hotplace;

    // 1. Create Base64 decoder stream instance
    decoder_stream stream(encoding_t::encoding_base64);

    // 2. Use stream operators for split chunk data input
    std::string chunk1 = "SGVsbG8g"; // "Hello "
    std::string chunk2 = "V29ybGQh"; // "World!"

    stream << chunk1;
    stream << chunk2;

    // 3. Extract decoded binary data (flush() invoked internally)
    binary_t decoded_bin = stream.data();
    std::string decoded_str(decoded_bin.begin(), decoded_bin.end());

    std::cout << "Decoded String: " << decoded_str << std::endl;

    return 0;
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-DECODER-01** | `HIGH` | **Expand `encoding_base16rfc` Decoding Pipeline**<br><br>- Implement explicit decoding logic for unsupported `encoding_base16rfc` and integrate into pipeline | `Postponed` | Not started |
| **TODO-DECODER-02** | `MEDIUM` | **Refine Base64 Residual Byte Mismatch Error Codes**<br><br>- Explicitly refine error codes and exception handling for single residual byte misinputs within `flush()` | `In Progress` | In progress |
| **TODO-DECODER-03** | `MEDIUM` | **Build Buffer Overrun Rollback & Safety Handling**<br><br>- Implement rollback and exception safety verification logic for existing stream buffers on `_maxsize` overrun | `Postponed` | Not started |
| **TODO-DECODER-04** | `LOW` | **Add Unit Tests for Buffer Reset Safety on Move Assignment**<br><br>- Implement unit tests to strengthen buffer state reset safety during C++11 Move assignment | `Postponed` | Not started |

---
