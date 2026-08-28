# Base64 / Base64URL Encoding & Decoding (`base64`) - published by Gemini

## 1. Overview & Key Features

The `base64` module is a core C++11 module providing Base64 and Base64URL encoding/decoding functionality in compliance with RFC 4648 standards and RFC 7515 (JWS Appendix C) specifications.
* **Dual Support for Standard & URL-Safe Specifications**: Supports mode selection for `encoding_base64` (`+`, `/`, `=` padding) and `encoding_base64url` (`-`, `_`, no padding).
* **Bitfield Union-Based High-Speed Conversion**: Maps 3-byte (24-bit) data into four 6-bit fields (`e1`, `e2`, `e3`, `e4`) using a `union` structure for fast and intuitive encoding.
* **Text Reconstruction Interface**: Provides the `base64_decode_careful` interface, which directly returns decoded data as an `std::string` when the payload is text.
* **C++11 Metaprogramming & Move Semantics**: Features a template-based two-phase memory allocation pattern (Reserve-Commit) using `custom::encoder_stream_traits` and SFINAE (`std::enable_if`), with optimizations for `std::string::data()` overloads and Move Semantics.

---

## 2. Key Implementation Areas & Technical Elements


* **Bitfield Bit-Shift Optimization**: Directly maps a 24-bit integer to four 6-bit indices via the `base64_conv_t` `union`, reducing masking operation overhead and maximizing bit conversion performance.
* **RFC 7515 Appendix C Compliant Parsing**: Strictly applies rules for omitting padding characters (`=`) during Base64URL mode operation while executing alphabet table mapping (`-`, `_`) conversions.
* **Reserve-Commit Memory Allocation Pattern**: Applies a two-phase memory allocation template mechanism to ensure safe dynamic buffer allocation and prevent memory fragmentation.
* **Text-Safe Output Interface**: Protects null characters and encoding text boundaries via `base64_decode_careful`, reliably restoring content into `std::string`.

---

## 3. Major Data Structures, Classes & API Reference

### Core Data Structures

```cpp
namespace hotplace {

// Bit conversion union (24-bit <-> 4x 6-bit direct mapping)
typedef union {
    struct {
        unsigned char c1, c2, c3; // 8-bit * 3
    };
    struct {
        unsigned int e1 : 6, e2 : 6, e3 : 6, e4 : 6; // 6-bit * 4
    };
    uint32 i32;
} base64_conv_t;

} // namespace hotplace
```
[cite: 9]

### Low-Level C-Style API (`hotplace::lowlevel` namespace)[cite: 9]

```cpp
namespace hotplace {
namespace lowlevel {

// Low-level operation functions utilizing two-phase buffer memory allocation
return_t base64_encode(const byte_t* source, size_t source_size, char* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_decode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);

}  // namespace lowlevel
}  // namespace hotplace
```
[cite: 9]

### Main High-Level APIs[cite: 9]

| API Name | Description & Functionality |
| --- | --- |
| `base64_encode(...)` | Encodes inputs with overloads for `const char*`, `std::string`, `binary_t`, `basic_stream`, etc[cite: 9]. |
| `base64_decode(...)` | Decodes input data into `binary_t` or a template stream buffer[cite: 9]. |
| `base64_decode_careful(...)` | Dedicated interface for safely returning text payload source data as an `std::string`[cite: 9]. |

---

## 4. Operational Principles[cite: 9]
1. **Two-Phase Buffer Allocation (Reserve & Commit Pattern)**:
   * **Phase 1 Call**: Passes `nullptr` to the `buffer` pointer to calculate required buffer size (`size_need`) and returns an `errorcode_t::insufficient_buffer` status[cite: 9].
   * **Phase 2 Call**: Allocates memory via `traits::reserve`, executes encoding/decoding, and finalizes the written byte size via `traits::commit`[cite: 9].
2. **Bit Mapping & Alphabet Conversion**:
   * Loads the input byte stream in 3-byte chunks into the `base64_conv_t` union[cite: 9].
   * Binds characters based on indices aligned in 6-bit units (`e1`–`e4`) according to the selected mode (`encoding_base64` or `encoding_base64url`)[cite: 9].
3. **Specification Padding & Termination**:
   * `encoding_base64`: Uses `+`/`/` for the 62nd/63rd characters and appends `=` padding when falling short of a 3-byte boundary[cite: 9].
   * `encoding_base64url`: Uses `-`/`_` characters and omits `=` padding per RFC 7515 Appendix C, terminating early after calculating shortened lengths[cite: 9].

---

## 5. Usage Example (C++11 Standard)[cite: 9]

```cpp
#include <iostream>
#include <string>
#include <hotplace/sdk/base/basic/base64.hpp>

int main() {
    using namespace hotplace;

    std::string text = "Base64 & Base64URL Test";

    // 1. Standard Base64 Encoding
    std::string b64_std = base64_encode(text, encoding_t::encoding_base64);
    std::cout << "Base64 Standard: " << b64_std << std::endl;

    // 2. Base64URL Encoding (URL-Safe, No Padding)
    std::string b64_url = base64_encode(text, encoding_t::encoding_base64url);
    std::cout << "Base64URL: " << b64_url << std::endl;

    // 3. Dedicated Text-Safe Decoding (base64_decode_careful)
    std::string restored_text = base64_decode_careful(b64_url, encoding_t::encoding_base64url);
    std::cout << "Restored: " << restored_text << std::endl;

    return 0;
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-BASE64-01** | `HIGH` | **Strengthen Invalid Input Validation & Error Handling**<br><br>- Add validation logic for invalid Base64 characters within the `base64_decode` loop | `Postponed` | Not started |
| **TODO-BASE64-02** | `MEDIUM` | **Refine Base64URL Omitted Padding Validation**<br><br>- Implement precise validation logic for omitted trailing padding (`=`) in Base64URL decoding | `Postponed` | Not started |
| **TODO-BASE64-03** | `LOW` | **Review Performance Gains via SIMD/AVX2**<br><br>- Review SIMD/AVX2 application to accelerate encoding/decoding loop performance for large `binary_t` buffers | `Postponed` | Not started |

---
