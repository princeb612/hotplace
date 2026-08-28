# Universal Error Handler (`return_t`) - published by Gemini

## 1. Overview & Key Features

The `return_t` structure is a C++11 universal error handling wrapper designed to unify disparate error code systems from operating systems (Linux `errno`, Windows `DWORD`/`HRESULT`) and external libraries (OpenSSL, ODBC, etc.) into a single, cohesive type.

* **Heterogeneous Platform/Library Error Integration**: Unifies Linux `errno`/`EAI_*`, Windows API `GetLastError()`, `HRESULT`, and user-defined error codes (`errorcode_t`).
* **Transparent Type Conversions**: Provides implicit/explicit constructors, assignment operators, and `constexpr` casting operators for `uint32`, `int`, `errorcode_t`, and `HRESULT`, ensuring full backward compatibility and seamless integration with existing codebases.
* **Metadata & Categorization Support**: Integrates with the `error_advisor` singleton class to provide error names (`error_code`), detailed description messages (`error_message`), and classification by severity/attributes (`category`).
* **Pipeline & Error Traits Integration**: Specializes `error_traits<return_t>` to act as the standard interface for validating success/failure states within `function_pipeline` execution chains.

---

## 2. Key Implementation Areas & Technical Elements

* **Implicit/Explicit Type Bridging**: Enables seamless conversion to and from integer and enum types, allowing developers to extend error handling return types without refactoring overhead.
* **Advisor-Driven Metadata Lookup**: Employs an internal mapping table (`error_descriptions`) managed by the `error_advisor` singleton, minimizing runtime string parsing overhead while supplying rich logging metadata.
* **OS Error Abstraction (`get_lasterror`)**: Abstracts system-level and socket-level errors across different operating systems into standardized `return_t` instances.
* **Pipeline-Aware Error Traits**: Leverages `error_traits` specialization (`is_success`, `is_not_fail`) to quickly determine whether to proceed with or interrupt execution pipelines.

---

## 3. Major Data Structures, Classes & API Reference

### 1) `return_t` Struct & `error_advisor` Class Declaration

```cpp
namespace hotplace {

struct return_t {
    uint32 code;

    return_t() : code(static_cast<uint32>(errorcode_t::success)) {}
    return_t(uint32 value) : code(value) {}
    return_t(int value) : code(static_cast<uint32>(value)) {}
    return_t(errorcode_t value) : code(static_cast<uint32>(value)) {}

    std::string error_code() const;
    std::string error_message() const;
    error_category_t category() const;

    constexpr operator uint32() const { return code; }
    constexpr operator errorcode_t() const { return static_cast<errorcode_t>(code); }
};

class error_advisor {
   public:
    static error_advisor* get_instance();

    bool error_code(return_t error, std::string& code);
    bool error_message(return_t error, std::string& message);
    bool error_message(return_t error, std::string& code, std::string& message);

    error_category_t categoryof(return_t code);
};

}  // namespace hotplace
```
[cite: 17]

### 2) Core APIs, Constants & Enum Reference[cite: 17]

| Category | Identifier | Description |
| --- | --- | --- |
| **Constants** | `ERROR_CODE_BEGIN` (`0xef010000`) | Starting offset for `hotplace` critical error codes[cite: 17]. |
| | `WARN_CODE_BEGIN` (`0xff010000`) | Starting offset for warnings and non-fatal error codes[cite: 17]. |
| **Error Categories** | `error_category_t` | Categorization enum: `success`, `expect_failure`, `severe`, `not_supported`, `low_security`, `trivial`, `warn`[cite: 17]. |
| **Helper Functions** | `get_lasterror(code, flags)` | Retrieves OS or Socket API errors and converts them into `return_t`[cite: 17]. |
| **Template Specialization** | `error_traits<return_t>` | Provides success/failure validation (`is_success`, `is_not_fail`) for pipeline integration[cite: 17]. |

---

## 4. Operational Principles[cite: 17]
1. **Error Code Construction & Conversion**:
   * Initializes to `errorcode_t::success` by default and utilizes C++11 `constexpr` conversion operators for zero-overhead compile-time comparisons with existing `uint32` and `errorcode_t` conditions[cite: 17].
2. **Error Metadata Lookup (`error_advisor`)**:
   * Calling `error_code()`, `error_message()`, or `category()` queries the `error_advisor::get_instance()` singleton to map numeric values back to human-readable code names, description messages, and severity categories[cite: 17].
3. **Platform Error Capture & Pipeline Dispatch**:
   * `get_lasterror()` captures platform-specific error states and wraps them into `return_t`, while `error_traits<return_t>` allows execution pipelines to evaluate success/failure states instantly[cite: 17].

---

## 5. Usage Example (C++11 Standard)[cite: 17]

```cpp
#include <iostream>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/system/error.hpp>

// Mock API Function
hotplace::return_t do_something(bool fail) {
    if (fail) {
        return hotplace::errorcode_t::invalid_parameter;
    }
    return hotplace::errorcode_t::success;
}

int main() {
    using namespace hotplace;

    // 1. Instantiation and assignment
    return_t ret = do_something(false);

    if (ret == errorcode_t::success) {
        std::cout << "[SUCCESS] Code: " << ret.code << std::endl;
    }

    // 2. Error handling and metadata retrieval
    ret = do_something(true);

    if (ret != errorcode_t::success) {
        std::cout << "[FAILED]" << std::endl;
        std::cout << " - Error Code String : " << ret.error_code() << std::endl;
        std::cout << " - Error Message     : " << ret.error_message() << std::endl;
        std::cout << " - Category          : "
                  << static_cast<int>(ret.category()) << std::endl;
    }

    // 3. System error translation (get_lasterror)
    return_t sys_err = get_lasterror(-1);
    std::cout << "System Error Code String: " << sys_err.error_code() << std::endl;

    return 0;
}
```
[cite: 17]

---

## 6. TODO List[cite: 17]

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-RET-01** | `HIGH` | **Expand C++11 `constexpr` Comparison Operators**<br>- Add compile-time comparison operators between `return_t` and various integer types | `Fixed` | Enhanced `constexpr` in `error.hpp`[cite: 17] |
| **TODO-RET-02** | `HIGH` | **Strengthen Linux `EAI_*` Error Offset OOB Validation**<br>- Enhance exception handling for out-of-bound system error codes in `get_lasterror` | `Fixed` | Modified `error.cpp`[cite: 17] |
| **TODO-RET-03** | `MEDIUM` | **Implement Dynamic Error Registration API in `error_advisor`**<br>- Add runtime registration interface for module-specific custom error definitions and messages | `Postponed` | Pending singleton extension[cite: 17] |
| **TODO-RET-04** | `MEDIUM` | **Optimize Windows `HRESULT`/`DWORD` Formatting**<br>- Add null pointer checks on `FormatMessageA` failure, handle `FACILITY_WIN32` conversion, and trim `\r\n` | `Fixed` | Applied in `error.cpp`[cite: 17] |

---
