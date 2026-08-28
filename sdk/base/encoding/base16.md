# Base16 Encoding/Decoding (`base16`) - published by Gemini

## 1. Overview & Key Features

The `base16` module is a core C++11 module responsible for RFC 4648-compliant Base16 (Hex) encoding, decoding, and handling RFC standard patterns.

* **High-Performance Low-Level Conversion**: Applies direct conversion based on bitwise shift operations and bitmap lookup tables (`conv_fast`, `hex_digits`) instead of `snprintf` to deliver optimal conversion speeds.
* **Flexible High-Level Interface**: Supports direct conversions between various C++ standard/custom containers such as `std::string`, `binary_t`, and `basic_stream`.
* **RFC-Specific Format Processing (`base16_encode_rfc`, `base16_decode_rfc`)**:
  * Supports parsing decimal array literals (`[227, 197, 117, ...]`) in RFC 7516 style.
  * Supports delimiter formats (`00:01:02:...`) in RFC 7539 style, as well as handling data containing spaces and line breaks.
* **Special Format & Validation Features**: Includes odd-size length decoding support for NIST CAVP test vectors and automatic detection/skipping of "0x" prefixes.
* **C++11 Metaprogramming & Move Semantics**: Implements a two-phase memory allocation pattern (Reserve-Commit) based on SFINAE (`std::enable_if`) and `custom::encoder_stream_traits`, while optimizing temporary object returns via Move Semantics (`std::move`).

---

## 2. Key Implementation Areas & Technical Elements

* **Lookup Table & Bitwise Speedup**: Maximizes encoding and decoding throughput by eliminating string formatting overhead and processing serialization via bit manipulation and lookup tables.
* **Reserve-Commit Memory Pattern**: Prevents unnecessary memory reallocations and guarantees safety during dynamic buffer allocation through a two-stage memory allocation template mechanism.
* **Leading Zero Neutral Comparison**: Removes leading '0' characters via `base16_compare` to compare semantic equality at the byte stream level.
* **Flexible Input Parsing Pipeline**: Features a specialized decoder pipeline that flexibly suppresses or parses RFC format-specific delimiters (colons, commas, brackets, etc.) and prefixes (`0x`).

---

## 3. Major Data Structures, Classes & API Reference

### Core C-Style API (`hotplace::lowlevel` namespace)

```cpp
namespace hotplace {
namespace lowlevel {

// Low-level functions for buffer size calculation (Phase 1) and memory copy conversion (Phase 2)
return_t base16_encode(const byte_t* source, size_t size, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_decode(const char* source, size_t size, byte_t* buf, size_t* buflen);

}  // namespace lowlevel
}  // namespace hotplace

```

### Main High-Level APIs

| API Name | Description & Functionality |
| --- | --- |
| `base16_encode(...)` | Encodes binary input data of various types into Hex strings or containers. |
| `base16_decode(...)` | Decodes Hex strings into `binary_t` or specified containers. |
| `base16_encode_rfc(...)` / `base16_decode_rfc(...)` | APIs handling decimal array literals, colon/space/line break delimited formats. |
| `base16_compare(...)` | Compares semantic byte equality after stripping leading zeros ('0'). |

---

## 4. Operational Principles

1. **Two-Phase Buffer Allocation (Reserve & Commit Pattern)**:
  * **Phase 1 Call**: Passes `nullptr` to the `buf` pointer to receive the required buffer size (`size_reserve`) and gets an `errorcode_t::insufficient_buffer` status.
  * **Phase 2 Call**: Allocates memory corresponding to that size via `traits::reserve`, executes the actual conversion, and finalizes the size via `traits::commit`.
2. **Encoding Flag Control (`flags`)**:
  * `encoding_flag_t::encoding_base16_capital`: Outputs in uppercase Hex ("0123456789ABCDEF").
  * `encoding_flag_t::encoding_base16_space`: Adds space (' ') delimiters between bytes.
  * `encoding_notrunc`: Appends data without truncating the existing output buffer.
3. **RFC Decoding Preprocessing**: Iterates through input to apply `0x` prefix skipping, ignoring comma (`,`) and colon (`:`) delimiters, and adjusting the upper nibble for odd-length inputs to restore the byte array.

---

## 5. Usage Example (C++11 Standard)

```cpp
#include <iostream>
#include <string>
#include <hotplace/sdk/base/basic/base16.hpp>

int main() {
    using namespace hotplace;

    // 1. Basic Encoding & Decoding
    std::string text = "Hello Base16!";
    std::string encoded = base16_encode(text);
    std::cout << "Encoded: " << encoded << std::endl;

    binary_t decoded_bin;
    base16_decode(encoded, decoded_bin);

    // 2. RFC Format Decoding (Decimal Array Format)
    std::string rfc_dec_array = "[72, 101, 108, 108, 111]";
    binary_t rfc_decoded;
    base16_decode_rfc(rfc_dec_array, rfc_decoded);

    // 3. RFC Format Encoding (Uppercase + Delimiter)
    std::string rfc_encoded = base16_encode(text, encoding_flag_t::encoding_base16_capital | encoding_flag_t::encoding_base16_space);
    std::cout << "RFC Format Encoded: " << rfc_encoded << std::endl;

    return 0;
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| ~~**TODO-ENC-01**~~ | `HIGH` | **Refactor `base16_encode_rfc` / `base16_decode_rfc` & Apply Exception Handling** | `Fixed` | Reflected in `base16rfc.cpp`<br> |
| ~~**TODO-ENC-02**~~ | `LOW` | **Add `test_base16_rfc` Boundary Condition / Invalid Input Test Cases**<br><br>- Reflected test cases for overflow (`300`), odd Hex, and `0x` prefix inclusion | `Fixed` | Reflected in `testcase_base16.cpp`<br> |
| **TODO-ENC-03** | `LOW` | **Review SIMD/AVX2 Vectorization Acceleration**<br><br>- Implement acceleration after reviewing portability and PQC/PKCS#11 integration | `Postponed` | Postponed pending portability and integration review |

---
