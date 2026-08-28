## Compile-time & Runtime String Obfuscation - published by Gemini

### 1. Overview and Design Pattern

This module is a **Runtime/Compile-Time String Obfuscation Library** designed to prevent sensitive plaintext literal strings from being exposed in binary files by taking advantage of C++11 runtime features and C++14 `constexpr` compile-time capabilities.

#### Key Features

* **Compile-time Encryption**: Transforms string literals into obfuscated data arrays at compile time using C++14 `constexpr` templates and customizable factor keys.
* **Anti-Reverse Engineering**: Blocks extraction of sensitive information (such as API keys, internal URLs, and passwords) via the `strings` command or binary decompilers (e.g., IDA, Ghidra).
* **C++11 Runtime & C++14 Compile-time Compliance**:
  * **Runtime**: Supports dynamic data ingestion via stream operators (`<<`, `+=`, `assign`, `append`) under C++11 execution environments.
  * **Compile-time**: Evaluated at compile-time using C++14 `constexpr` constructor body capabilities.
* **Stream & Binary Interoperability**: Decrypted dynamic content easily transfers to standard output channels or stream types (`std::string`, `basic_stream`, `binary_t`).

---

### 2. Core Classes, Structs, and API Reference

#### 1) `constexpr_obfuscate.hpp` (Compile-time Helper)

C++14 compile-time template class and helper macros that perform additive factor transformation on string byte arrays.

```cpp
#ifndef __HOTPLACE_SDK_BASE_STRING_CONSTEXPROBFUSCATE__
#define __HOTPLACE_SDK_BASE_STRING_CONSTEXPROBFUSCATE__

#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

#if __cplusplus >= 201402L  // C++14

#define define_constexpr_obf(var, x) constexpr auto var = CONSTEXPR_OBF(x)
#define CONSTEXPR_OBF(x) t_constexpr_obf<RTL_NUMBER_OF(x)>(x)
#define CONSTEXPR_OBF_F(f, x) t_constexpr_obf<RTL_NUMBER_OF(x), f>(x)
#define CONSTEXPR_OBF_STR(x) x.load_string()
#define CONSTEXPR_OBF_CSTR(x) x.load_string().c_str()

template <uint32 N, uint8 F = 0x30>
class t_constexpr_obf {
   public:
    constexpr t_constexpr_obf(const char* source);

    std::string load_string() const;
    size_t size() const;

   private:
    char buf[N + 1] = { 0, };
    uint8 factor = F;
};

#endif

}  // namespace hotplace

#endif

```

#### 2) `obfuscate_string.hpp` (Runtime Interface)

Class for obfuscating and stream-processing strings dynamically at runtime.

```cpp
#ifndef __HOTPLACE_SDK_BASE_STRING_OBFUSCATESTRING__
#define __HOTPLACE_SDK_BASE_STRING_OBFUSCATESTRING__

#include <hotplace/sdk/base/stream/types.hpp>
#include <string>

namespace hotplace {

class obfuscate_string {
   public:
    obfuscate_string();
    obfuscate_string(const char* source);
    obfuscate_string(std::string& source);
    obfuscate_string(basic_stream& source);
    ~obfuscate_string();

    // Data Assignment and Insertion
    obfuscate_string& assign(const char* source, size_t size);
    obfuscate_string& append(const char* source, size_t size);

    // Capacity and Comparison
    size_t size() const;
    bool empty() const;
    bool compare(obfuscate_string& o) const;

    // Overloaded Operators
    obfuscate_string& operator=(const char* source);
    obfuscate_string& operator=(std::string& source);
    obfuscate_string& operator=(basic_stream& source);

    obfuscate_string& operator+=(const char* source);
    obfuscate_string& operator+=(std::string& source);
    obfuscate_string& operator+=(basic_stream& source);

    obfuscate_string& operator<<(const char* source);
    obfuscate_string& operator<<(std::string& source);
    obfuscate_string& operator<<(basic_stream& source);

    bool operator==(obfuscate_string& o) const;
    bool operator!=(obfuscate_string& o) const;

    // Stream Output Friend Operators
    friend std::string& operator<<(std::string& lhs, const obfuscate_string& rhs);
    friend basic_stream& operator<<(basic_stream& lhs, const obfuscate_string& rhs);
    friend binary_t& operator<<(binary_t& lhs, const obfuscate_string& rhs);

   protected:
    void startup();
    void cleanup();

   private:
    uint32 _flags;
    byte_t _factor;
    binary_t _contents;
};

}  // namespace hotplace

#endif

```

---

### 3. Usage Examples

#### 1) Compile-time Obfuscation Example (`t_constexpr_obf`)

```cpp
#include <iostream>
#include <hotplace/sdk/base/string/constexpr_obfuscate.hpp>

void example_constexpr_obf() {
#if __cplusplus >= 201402L  // C++14
    constexpr auto temp1 = hotplace::t_constexpr_obf<24>("ninety nine red balloons");
    constexpr auto temp2 = CONSTEXPR_OBF("wild wild world");
    define_constexpr_obf(temp3, "still a man hears what he wants to hear and disregards the rest");

    std::cout << CONSTEXPR_OBF_CSTR(temp1) << std::endl;
    std::cout << CONSTEXPR_OBF_CSTR(temp2) << std::endl;
    std::cout << CONSTEXPR_OBF_CSTR(temp3) << std::endl;
#endif
}

```

#### 2) Runtime Obfuscation & Stream Operators Example (`obfuscate_string`)

```cpp
#include <cstring>
#include <string>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/string/obfuscate_string.hpp>

void example_runtime_obf() {
    using namespace hotplace;

    char helloworld[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0};

    // Constructor initialization
    obfuscate_string obf = helloworld;
    obfuscate_string obf2 = helloworld;

    // Stream extraction into binary container
    binary_t bin;
    bin << obf;

    // Stream extraction into standard string
    std::string str;
    str << obf;

    // Appending dynamic data
    obf << helloworld;
    obf2 << helloworld;

    // Comparison verification
    if (obf == obf2) {
        // Both containers hold identical obfuscated content
    }
}

```

---

### 4. TODO List Tracker

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-OBF-01** | `HIGH` | **Implement Dynamic Seed-based Compile-time Key Generation**<br><br>- Enhance C++14 `constexpr` key generation using dynamic factors/seeds | `To Do` | `constexpr_obfuscate.hpp`<br> |
| **TODO-OBF-02** | `HIGH` | **Extend Multi-byte XOR / AES-CTR Compile-time Algorithms**<br><br>- Upgrade factor-based algorithm to multi-byte keystream obfuscation leveraging C++14 `constexpr`<br> | `In Progress` | Enhance obfuscation strength |
| **TODO-OBF-03** | `MEDIUM` | **Apply Guaranteed Runtime Memory Zeroing Functions**<br><br>- Ensure `cleanup()` zeroizes `_contents` memory securely to prevent sensitive data leakage | `To Do` | `obfuscate_string.cpp`<br> |
| **TODO-OBF-04** | `MEDIUM` | **Add C++11 Compatible `std::string_view`-like Casting Operators**<br><br>- Extend interface operators within C++11 standard scope for smoother stream integration | `To Do` | Supplement convenience features |
| **TODO-OBF-05** | `MEDIUM` | **Add C++11 / C++14 Version Separation Verification Conditionals**<br><br>- Ensure strict separation of `t_constexpr_obf` using `#if __cplusplus >= 201402L` preprocessor guards | `To Do` | Ensure compatibility |
| **TODO-OBF-06** | `LOW` | **Write Obfuscator Usage Examples and Review Comments**<br><br>- Add explicit Doxygen comments and usage examples for `t_constexpr_obf` and `obfuscate_string`<br> | `In Progress` | Documentation tasks |
