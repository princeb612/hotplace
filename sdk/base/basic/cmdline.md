# `t_cmdline_t` & `t_cmdarg_t` - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

`cmdline.hpp` module은 Command Line Arguments parsing을 타입 안전(Type-safe)하고 직관적으로 처리하기 위해 설계된 C++11 template 기반 parser

### 주요 특징

1. **커스텀 option 구조체 연동**: 구조체/class template(`T`)을 type parameter로 받아, parsing 결과를 해당 구조체 객체에 직접 binding
2. **Fluent Interface & Move Semantics**: `<<` 연산자와 이동 생성자/이동 대입 연산자(Move Semantics)를 통해 option 등록을 chaining 방식으로 명확하게 작성할 수 있음
3. **선택적/필수 및 값 동반 flag 제어**:
  * `preced()`: 인자 뒤에 값이 반드시 따라오는 option (예: `-in FILENAME`).
  * `optional()`: 생략 가능한 option (설정하지 않으면 필수 option으로 지정됨).
4. **ANSI 색상 지원 Help 출력**: 필수 항목과 parsing 여부를 구분하여 terminal 화면에 시각적으로 guide(`help()`)를 제공.

---

## 2. 핵심 class 및 API 구조 분석 (API Reference)

### flag 정의

```cpp
enum cmdline_flag_t : uint32 {
    cmdline_preced   = (1 << 1),  // Expects a value in the next token
    cmdline_optional = (1 << 2),  // Optional parameter
};

```

### 주요 class 및 method

| class / method | 역할 및 기능 |
| --- | --- |
| **`t_cmdarg_t<T>`** | 개별 command line option 정의 class. |
| `t_cmdarg_t(token, desc, func)` | option token명, 설명, binding callback lambda(`std::function`)를 등록함. |
| `.preced()` | 인자가 후속 값(value)을 요구함을 지정. (`lvalue` / `rvalue` method chaining 지원). |
| `.optional()` | option을 선택 사항으로 지정. (지정하지 않을 경우 필수 option으로 취급). |
| **`t_cmdline_t<T>`** | option 모음 관리 및 parsing 수행 class. |
| `operator<<(t_cmdarg_t&&)` | option 객체를 이동 생성으로 등록함 (중복 token 발생 시 예외 던짐). |
| `parse(argc, argv)` | command line 인자를 순회하며 등록된 lambda를 호출하고 필수 option 누락 여부를 검증함. |
| `value()` | parsing 결과가 담긴 타입 `T` 객체의 상수 참조 반환. |
| `help()` | 등록된 option 목록 및 도움말을 formatted text로 출력. |

---

## 3. C++11 기반 실습 code (C++11 Example Usage)

`C++11` 규격에 준수

```cpp
#include <iostream>
#include <hotplace/sdk/base/basic/cmdline.hpp>

// Program option structure
struct program_options {
    std::string input_file;
    std::string output_file;
    bool generate_key;

    program_options() : generate_key(false) {}
};

int main(int argc, char** argv) {
    using namespace hotplace;

    // Create command line parser instance
    t_cmdline_t<program_options> cmdline;

    try {
        // Register arguments using operator<< and rvalue move-chaining
        cmdline
            << t_cmdarg_t<program_options>("-in", "Specify input file path",
                [](program_options& opt, const char* param) -> void {
                    opt.input_file = param;
                }).preced()
            << t_cmdarg_t<program_options>("-out", "Specify output file path",
                [](program_options& opt, const char* param) -> void {
                    opt.output_file = param;
                }).preced().optional()
            << t_cmdarg_t<program_options>("-keygen", "Generate security key",
                [](program_options& opt, const char* param) -> void {
                    opt.generate_key = true;
                }).optional();

        // Parse command line arguments
        return_t ret = cmdline.parse(argc, argv);

        if (errorcode_t::success != ret) {
            std::cout << "[Warning] Invalid command line arguments!\n\n";
            cmdline.help();
            return ret;
        }

        // Retrieve parsed result
        const program_options& opt = cmdline.value();
        std::cout << "[Config] Input file  : " << opt.input_file << "\n";
        std::cout << "[Config] Output file : " << opt.output_file << "\n";
        std::cout << "[Config] Keygen mode : " << (opt.generate_key ? "ENABLED" : "DISABLED") << "\n";

    } catch (const exception& e) {
        std::cerr << "[Error] Exception caught: " << e.what() << "\n";
        return e.get_code();
    }

    return errorcode_t::success;
}

```

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`cmdline.hpp` module의 고도화 및 유지보수를 위한 번호 체계 기반 TODO 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| ~~TODO-CL-01~~ | `HIGH` | **GCC 4.8.5 `noexcept = default` 호환성 점검**<br>- header 내 주석 처리된 `GCC 4.8.5 bug` 대응 code 제거 가능 여부 테스트 및 C++11 표준 보완 | `Won't Fix` | 이동 생성자/대입연산자 |
| ~~TODO-CL-02~~ | `HIGH` | **중복 option 입력 처리 정책 검토**<br>- command line에 동일한 option이 중복 입력되었을 때 덮어쓰기/error return 중 선택 정책 추가 | `Won't Fix` | `parse()` loop 내 처리 |
| **TODO-CL-03** | `MEDIUM` | **Short/Long option 앨리어싱(Aliasing) 지원**<br>- `-i` / `--input` 형태의 별칭 token binding 기능 지원 검토 | `To Do` | `_args` 맵 구조 개선 |
| **TODO-CL-04** | `MEDIUM` | **`help()` 함수 출력 포맷 다변화 및 개행 처리 개선**<br>- ANSI escape code 사용 불가 환경(Windows 구버전 등) switch flag 제공 | `To Do` | Console API 연동 |
| ~~**TODO-CL-05**~~ | `LOW` | **소멸자 및 가상 함수 구조 정리**<br>- `t_cmdline_t` 및 `t_cmdarg_t` class의 상속 여부에 따른 Virtual Destructor 명시 검토 | `Fixed` | final 처리 |

---
