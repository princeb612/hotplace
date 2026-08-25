# `function_pipeline` - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

`function_pipeline` module은 여러 단계의 작업(함수 call)을 chaining(Fluent Interface/Method Chaining) 기법으로 엮어 **오류 발생 시 연속 실행을 제어하고, resource 해제(rollback) 및 예외 처리를 깔끔하게 캡슐화**하기 위한 체인 pattern(Chain Pattern) 기반 class template

### 주요 특징

1. **Fluent Interface (method chaining)**: `.run()`, `.walk()`, `.walk_failed()` 등의 함수를 이어 붙여 직관적인 pipeline 흐름을 구성할 수 있음
2. **다양한 return 타입 지원 (C++11 Template)**: 기본 return 타입 `return_t` 외에도 OpenSSL errorcode(`int`, `osslerror_category`) 등 사용자 정의 타입 및 error 카테고리를 지원
3. **조건부 실행 흐름 평가**: 설정된 판별자(`_discriminant`)에 따라 성공 시에만 다음 단계로 넘어가거나, 실패 시 rollback(`walk_failed`) 단계만 실행하도록 schedule링
4. **debugging 및 추적 (Trace) 지원**: `DEBUG` 빌드 시 호출된 파일명(`__FILE__`)과 줄 번호(`__LINE__`), 처리된 단계 비율(`processed / total`) 및 마지막 error code를 트레이스 시스템으로 자동 reporting

---

## 2. 핵심 class 및 API 구조 분석 (API Reference)

### template 정의

```cpp
template <typename T = return_t, typename category = void>
class function_pipeline;

```

### 주요 method 분석

| 구분 | method / macro | 설명 |
| --- | --- | --- |
| **parameter 검증** | `test_parameter(checker)` | 사전 검증 lambda 실행. 실패 시 `value_invalid_parameter()` 세팅. |
| **조건 설정** | `goahead_if_success()`<br>`goahead_if_not_fail()` | 성공 또는 치명적 error가 아닐 때 다음 작업 실행하도록 판별 기준 변경. |
| **핵심 실행** | `run(func)`<br>`run_pipe(lambda)` | 핵심 logic(함수)을 실행. 이전 작업이 성공일 때만 수행됨. |
| **예외 안전 실행** | `run_trycatch(func)` | 예외 발생 시 `value_exception()`을 세팅하고 pipeline을 중단. |
| **부수 작업 (Walk)** | `walk(func)`<br>`walk_failed(func)` | 반환값이 없는 보조 작업 실행. `walk_failed`는 앞선 작업 실패 시 (rollback 목적) 실행. |
| **결과 취득** | `result()` / `passed()`<br>`result_to_return_t()` | 최종 반환 code 취득 및 성공 여부 확인. `return_t` 포맷 변환 지원. |

---

## 3. C++11 기반 실습 code (C++11 Example Usage)

`C++11` 규격

```cpp
#include <iostream>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>

// Dummy target class for testing pipeline
class resource_manager {
public:
    hotplace::return_t initialize() {
        // Assume initialization succeeded
        return hotplace::errorcode_t::success;
    }

    hotplace::return_t process_step1() {
        // Step 1 logic
        return hotplace::errorcode_t::success;
    }

    hotplace::return_t process_step2() {
        // Step 2 failed example
        return hotplace::errorcode_t::internal_error;
    }

    void rollback() {
        // Rollback operations on failure
        std::cout << "[Rollback] Reverting changes due to pipeline failure.\n";
    }
};

int main() {
    using namespace hotplace;

    resource_manager res;
    int* ptr = &res ? new int(10) : nullptr;

    // Create pipeline instance (C++11 based)
    function_pipeline<return_t> pipeline;

    pipeline.test_parameter([&]() -> bool {
                // Check initial argument validity
                return (nullptr != ptr);
            })
            .goahead_if_success()
            .walk([&]() -> void {
                // Logging or side-effect work before execution
                std::cout << "[Pipeline] Starting sequence...\n";
            })
            .run([&]() -> return_t {
                return res.initialize();
            })
            .run([&]() -> return_t {
                return res.process_step1();
            })
            .run([&]() -> return_t {
                return res.process_step2();
            })
            .walk_failed([&]() -> void {
                // Executes only if any preceding step fails
                res.rollback();
            })
            .walk_always([&]() -> void {
                // Always clean up dynamic memory regardless of success/failure
                if (ptr) {
                    delete ptr;
                    ptr = nullptr;
                }
            });

    std::cout << "Processed steps: " << pipeline.processed() << " / " << pipeline.size() << std::endl;
    std::cout << "Pipeline passed: " << (pipeline.passed() ? "true" : "false") << std::endl;

    return pipeline.result_to_return_t();
}
```

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`function_pipeline` module의 고도화 및 유지보수를 위한 번호 체계 기반 TODO 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-FP-01** | `HIGH` | **C++11 `std::move` 기반 lambda 캡처 성능 최적화 검토**<br>- 복사 비용이 큰 객체의 우회 방지 및 우측값 참조 활용 확장 | `To Do` | `runner` 구조 개선 |
| **TODO-FP-02** | `HIGH` | **DEBUG 모드 내 `run_pipe` macro 일관성 검증**<br>- `__FILE__`, `__LINE__` 추적 누락 구간 점검 및 비-debug 빌드와의 interface 정합성 확인 | `In Progress` | `set_tracer` 및 `handle_result` |
| **TODO-FP-03** | `MEDIUM` | **비동기/Future 대응 pipeline 확장 설계**<br>- `std::future` / 비동기 lambda pattern 결합 가능 여부 조사 | `To Do` | 차기 버전 고려 |
| **TODO-FP-04** | `MEDIUM` | **C++11 error 카테고리 trait 확장**<br>- `error_traits` template의 커스텀 error 타입 추가 등록 및 변환 unit test 작성 | `To Do` | `osslerror_category` 외 추가 |
| **TODO-FP-05** | `LOW` | **단구현 레벨 소스 code 내부 주석 영문화 검수**<br>- Doxygen tag 형식 정합성 및 영문 표현 가독성 보완 | `In Progress` | Header 문서화 |

---
