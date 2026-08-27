# Compile-time & Runtime String Obfuscation (문자열 난독화) - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

본 module은 C++11 runtime 환경과 C++14 `constexpr` compile-time 특성을 활용하여, 바이너리 내에 평문(Plaintext) literal 문자열이 노출되는 것을 방지하기 위해 설계된 **Compile-Time String Obfuscation Library**

### 주요 특징

* **compile-time 난독화 (Compile-time Encryption)**: C++14 `constexpr` 및 시드(XOR key, 난수 seed)를 활용해 문자열 literal을 compile-time에 난독화 데이터 배열로 전환.
* **리버스 엔지니어링 방지**: `strings` 명령어나 바이너리 de-compiler(IDA, Ghidra 등)를 통한 민감 정보(API Key, 내부 URL, password 등) 추출 차단.
* **C++11 Runtime & C++14 Compile-time 규격 준수**:
  * **Runtime**: C++11 기반 실행환경 지원.
  * **Compile-time**: C++14의 완화된 `constexpr` 제약 조건과 `<utility>` 표준 유틸리티(`std::make_index_sequence`, `std::index_sequence`)를 활용하여 구현.
* **RAII 및 자동 메모리 소거**: runtime 복호화 객체 생성 시 메모리에 복호화된 문자열을 배치하고, 객체 소멸 시 메모리를 소거(Zeroize/Clear)하여 메모리 덤프 공격에 대비.

---

## 2. 핵심 class, struct 및 API 구조 분석 (API Reference)

### 1) `constexpr_obfuscate.hpp` (Compile-time Helper)

C++14 compile-time 시점에 난독화 키를 생성하고 문자열 바이트 배열을 XOR 변환하는 메타프로그래밍 구조체

```cpp
#include <utility>
#include <cstddef>
#include <cstdint>

namespace hotplace {

// Compile-time XOR Obfuscator (C++14 constexpr & index_sequence)
template <std::size_t N, uint8_t KEY>
class constexpr_obfuscator {
public:
    // C++14 constexpr constructor: Evaluates XOR encryption at compile time using std::index_sequence
    template <std::size_t... Is>
    constexpr constexpr_obfuscator(const char (&str)[N], std::index_sequence<Is...>)
        : data_{ static_cast<char>(str[Is] ^ KEY)... } {}

    constexpr const char* get() const { return data_; }
    constexpr std::size_t size() const { return N; }

    char data_[N];
};

} // namespace hotplace

```

### 2) `obfuscate_string.hpp` & `obfuscate_string.cpp` (Runtime Interface)

C++11 runtime 시점에 난독화된 데이터를 복호화하고, 사용 완료 후 안전하게 해제하는 wrapper class

```cpp
#include <cstddef>
#include <cstdint>

namespace hotplace {

// C++11 Runtime RAII Wrapper
class obfuscate_string {
public:
    // Decrypts encrypted data at runtime using XOR key
    obfuscate_string(const char* encrypted_data, std::size_t len, uint8_t key);
    ~obfuscate_string();

    // Returns decrypted C-style string
    const char* c_str() const;
    std::size_t length() const;

    // Zeroizes and frees memory buffer
    void clear();

private:
    char* decrypted_buffer_;
    std::size_t size_;
};

} // namespace hotplace

```

### 3) 주요 API 및 macro

| 구분 | 이름 | 설명 |
| --- | --- | --- |
| **macro** | `OBFUSCATE_STR(str)` | C++14 compile-time 난독화 및 C++11 runtime 임시 복호화 객체 생성 helper |
| **핵심 macro** | `OBFUSCATE_KEY` | `__TIME__` 또는 `__LINE__` 기반 난수 키 생성 macro |
| **클래스** | `obfuscate_string` | C++11 runtime 버퍼 관리 및 메모리 Zeroize 담당 RAII 객체 |
| **helper 함수** | `decrypt_buffer()` | 난독화된 버퍼를 XOR 복호화하는 runtime 내부 함수 |

---

## 3. C++11 Runtime / C++14 Compile-time 실습 code (Example Usage)

```cpp
#include <iostream>
#include <utility>
#include <cstring>
#include <cstddef>
#include <cstdint>

// Helper macro for compile-time string obfuscation key
#define OBFUSCATE_KEY 0x5A

namespace hotplace {

// Encrypted string container evaluated at compile-time (C++14 constexpr & std::index_sequence)
template <std::size_t N, uint8_t KEY>
class constexpr_obfuscated_data {
public:
    template <std::size_t... Is>
    constexpr constexpr_obfuscated_data(const char (&str)[N], std::index_sequence<Is...>)
        : encrypted_data_{ static_cast<char>(str[Is] ^ KEY)... } {}

    constexpr const char* data() const { return encrypted_data_; }
    constexpr std::size_t size() const { return N; }
    constexpr uint8_t key() const { return KEY; }

private:
    char encrypted_data_[N];
};

// RAII Wrapper for C++11 runtime decryption
class obfuscate_string {
public:
    obfuscate_string(const char* enc_data, std::size_t size, uint8_t key)
        : size_(size), buffer_(new char[size]) {
        // Perform XOR decryption at C++11 runtime
        for (std::size_t i = 0; i < size_; ++i) {
            buffer_[i] = enc_data[i] ^ key;
        }
    }

    ~obfuscate_string() {
        clear();
    }

    const char* c_str() const {
        return buffer_;
    }

    std::size_t length() const {
        return size_;
    }

    void clear() {
        if (buffer_ != nullptr) {
            // Zeroize sensitive buffer before deallocation
            std::memset(buffer_, 0, size_);
            delete[] buffer_;
            buffer_ = nullptr;
        }
    }

private:
    std::size_t size_;
    char* buffer_;
};

} // namespace hotplace

int main() {
    // Compile-time obfuscation evaluated using C++14 std::make_index_sequence
    static constexpr hotplace::constexpr_obfuscated_data<14, OBFUSCATE_KEY> enc_str(
        "Sensitive_Key", std::make_index_sequence<14>{}
    );

    // Runtime decryption using C++11 RAII wrapper
    hotplace::obfuscate_string dec_str(enc_str.data(), enc_str.size(), enc_str.key());

    std::cout << "[Obfuscation Test]" << std::endl;
    std::cout << " - Decrypted String : " << dec_str.c_str() << std::endl;
    std::cout << " - String Length   : " << dec_str.length() << std::endl;

    return 0;
}

```
---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-OBF-01** | `HIGH` | **동적 시드(Dynamic Seed) 기반 Compile-time 키 생성 구현**<br>- `__TIME__` / `__LINE__` 기반 C++14 `constexpr` 시드 생성 알고리즘 보완 | `To Do` | `constexpr_obfuscate.hpp` |
| **TODO-OBF-02** | `HIGH` | **다중 바이트 XOR / AES-CTR compile-time 알고리즘 확장**<br>- C++14 `constexpr` 제어문을 활용한 가변 길이 키 스트림 난독화 적용 | `In Progress` | 난독화 강도 향상 |
| **TODO-OBF-03** | `MEDIUM` | **runtime 메모리 Zeroize 보장 함수 적용**<br>- 최적화에 의해 `memset`이 생략되지 않도록 `volatile` 키워드 또는 `RtlSecureZeroMemory` 처리 | `To Do` | `obfuscate_string.cpp` |
| **TODO-OBF-04** | `MEDIUM` | **C++11 호환 `std::string_view` 유사 캐스팅 연산자 추가**<br>- C++11 표준 범위 내 오버로드 연산자 확장 | `To Do` | 편의 기능 보완 |
| **TODO-OBF-05** | `MEDIUM` | **C++11 / C++14 버전 분리 검증 조건문 추가**<br>- `#if __cplusplus >= 201402L` 전처리기 조건문 기반 타깃 분리 처리 | `To Do` | 호환성 보장 |
| **TODO-OBF-06** | `LOW` | **Obfuscator 사용 예제 작성 및 주석 검수**<br>- C++14 `constexpr` / C++11 runtime 명시적 영문 주석 검수 및 Doxygen 추가 | `In Progress` | 문서화 작업 |
