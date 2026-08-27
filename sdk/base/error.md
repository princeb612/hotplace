
# `return_t` - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

`return_t` 구조체는 OS(Linux `errno`, Windows `DWORD`/`HRESULT`) 및 외부 라이브러리(OpenSSL, ODBC 등)의 서로 다른 오류 코드 체계를 단일 타입으로 통합 관리하기 위해 설계된 **Universal Error Handling wrapper**.

### 주요 특징

1. **이종 플랫폼/라이브러리 에러 타입 통합**: Linux `errno`/`EAI_*`, Windows API `GetLastError()`, `HRESULT` 및 사용자 정의 에러 코드(`errorcode_t`)를 통합 수용.
2. **투명한 타입 변환 (Implicit/Explicit Conversion)**: `uint32`, `int`, `errorcode_t`, `HRESULT` 등에 대한 생성자 및 대입 연산자, `constexpr` 캐스팅 연산자를 제공하여 기존 코드와의 하위 호환성 및 편의성 보장.
3. **오류 metadata 및 카테고리화 제공**: `error_advisor` singleton 클래스와 연동되어 단순 숫자값을 넘어서 에러 이름(`error_code`), 설명 메시지(`error_message`), 심각도 및 속성에 따른 분류(`category`) 기능 제공.
4. **`function_pipeline` module 및 `error_traits`와의 결합**: `error_traits<return_t>` 특수화를 통해 체인 구조의 pipeline에서 성공/실패 여부를 판단하는 표준 타입으로 활용.

---

## 2. 핵심 class, struct 및 API 구조 분석 (API Reference)

### 1) `return_t` 구조체

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

    // 대입 및 비교 연산자 (uint32, int, errorcode_t 등 지원)
    ...
};

}
```[cite: 4]

### 2) `error_advisor` 클래스 (Singleton)

오류 코드와 메시지의 매핑 테이블(`error_descriptions`)을 내부적으로 관리하며 metadata 조회를 담당[cite: 5, 6].

```cpp
class error_advisor {
public:
    static error_advisor* get_instance();

    bool error_code(return_t error, std::string& code);
    bool error_message(return_t error, std::string& message);
    bool error_message(return_t error, std::string& code, std::string& message);

    error_category_t categoryof(return_t code);
    ...
};
```
[cite: 6]

### 3) 주요 API 및 열거형

| 구분 | 이름 | 설명 |
| --- | --- | --- |
| **상수 영역** | `ERROR_CODE_BEGIN` (`0xef010000`) | `hotplace` 전용 치명적 에러 코드 시작 offset[cite: 4]. |
| | `WARN_CODE_BEGIN` (`0xff010000`) | 경고 및 비치명적 에러 코드 시작 offset[cite: 4]. |
| **에러 카테고리** | `error_category_t` | `success`, `expect_failure`, `severe`, `not_supported`, `low_security`, `trivial`, `warn` 분류[cite: 4]. |
| **helper 함수** | `get_lasterror(code, flags)` | OS 또는 소켓 API의 시스템 에러를 취득하여 `return_t`로 변환[cite: 3, 4]. |
| **특수화 템플릿** | `error_traits<return_t>` | 성공 여부 검증(`is_success`, `is_not_fail`) 및 pipeline 연동 인터페이스[cite: 6]. |

---

## 3. C++11 기반 실습 code (C++11 Example Usage)

`C++11` 규격

```cpp
#include <iostream>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/system/error.hpp>

// 모의 API 함수
hotplace::return_t do_something(bool fail) {
    if (fail) {
        return hotplace::errorcode_t::invalid_parameter;
    }
    return hotplace::errorcode_t::success;
}

int main() {
    using namespace hotplace;

    // 1. return_t 생성 및 대입 연산
    return_t ret = do_something(false);

    if (ret == errorcode_t::success) {
        std::cout << "[SUCCESS] Code: " << ret.code << std::endl;
    }

    // 2. 에러 발생 및 metadata 출력
    ret = do_something(true);

    if (ret != errorcode_t::success) {
        std::cout << "[FAILED]" << std::endl;
        std::cout << " - Error Code String : " << ret.error_code() << std::endl;
        std::cout << " - Error Message     : " << ret.error_message() << std::endl;
        std::cout << " - Category          : "
                  << static_cast<int>(ret.category()) << std::endl;
    }

    // 3. 시스템 에러 변환 (get_lasterror)
    return_t sys_err = get_lasterror(-1); // OS 에러 연동 테스트
    std::cout << "System Error Code String: " << sys_err.error_code() << std::endl;

    return 0;
}
```

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`return_t` 및 `error_advisor` module의 고도화를 위한 번호 체계 기반 TODO 항목

`error.md`의 **TODO List Tracker**의 **TODO 1, 2, 3** 항목 상태(Status)를 반영하여 업데이트한 전체 테이블은 다음과 같습니다.

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`return_t` 및 `error_advisor` module의 고도화를 위한 번호 체계 기반 TODO 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| ~~TODO-RET-01~~ | `HIGH` | **C++11 `constexpr` 비교 연산자 범위 확장**<br><br>- `return_t`와 다양한 정수형 타입 간의 compile-time 비교 연산자 추가 보완 | `Fixed`` | `error.hpp` 내 `constexpr` 보완 |
| ~~TODO-RET-02~~ | `HIGH` | **Linux `EAI_*` 에러 offset 변환 구간 OOB 검증 강화**<br><br>- `get_lasterror` 처리 시 시스템 범위 초과 에러 코드에 대한 예외 처리 보완 | `Fixed` | `error.cpp` 수정 |
| **TODO-RET-03** | `MEDIUM` | **`error_advisor` 동적 에러 테이블 등록 API 구현**<br><br>- module별 커스텀 에러 정의 및 메시지 runtime 등록 기능 확충 | `To Do` | singleton 확장 |
| ~~**TODO-RET-04**~~ | `MEDIUM` | **Windows `HRESULT`/`DWORD` 에러 문자열 포맷팅 서식 최적화**<br><br><br>- `FormatMessageA` 실패시 NPE 검증, `FACILITY_WIN32` 변환 및 `\r\n` 트림 처리 | `Fixed` | `error.cpp` 반영 |
