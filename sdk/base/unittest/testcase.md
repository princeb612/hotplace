# `test_case` framework - published by Gemini

## 1. 개요 및 설계 구조 (Overview & Architecture)

`test_case` module은 C++ 환경에서 단위 테스트(Unit Test)를 체계적으로 수행하고 결과를 집계·reporting하는 unit test library
멀티쓰레드 환경에서 쓰레드별 test case 관리 및 stopwatch(시간 측정) 기능을 지원

### 주요 특징

1. **쓰레드별 context 격리 (Per-Thread Context Management)**:
* 쓰레드 ID(`arch_t tid`)를 키값으로 test case 이름(`_testcase_per_threads`), stopwatch flag(`_time_flag_per_threads`), 타임스탬프(`_timestamp_per_threads`), 구간 시간 Slices(`_time_slice_per_threads`)를 독립적으로 관리함.
2. **구간 시간 측정 제어 (RAII Timer Control)**:
* `reset_time()`, `pause_time()`, `resume_time()`, `check_time()`을 제공하여 실제 검증 대상 code 구간만 정밀 측정 가능함.
* RAII pattern 기반의 `test_case_notimecheck` 스코프 가드를 통해 불필요한 구간(준비/정리 logic)의 시간 측정을 자동 일시정지/재개함.
3. **ANSI 컬러 서식화 stream 바인더 (`t_stream_binder`)**:
* `console_color`와 `basic_stream`을 wrapping하여 콘솔 출력 시 terminal text style 및 색상(성공/실패/경고 등)을 적용함.
4. **다양한 단정문 및 결과 분류**:
* `assert`, `vassert`, `nassert`, `test`, `ntest` 등 다양한 interface 제공.
* `error_advisor` 시스템을 통해 단정 결과를 `success`, `expect_failure`, `severe`, `not_supported`, `trivial`, `warn` 등의 카테고리로 자동 집계함.
5. **종합 reporting 기능 (`report`)**:
* 콘솔/로거 출력 및 `report` 파일 저장 지원함.
* 테스트 그룹별 패스/실패율 통계, 실패 케이스 상세 목록, Execution Time Top-N 정렬 리포트를 생성함.

---

## 2. 핵심 class 및 구조 분석 (API Reference)

### 주요 구성요소

* **`test_case`**: 단위 테스트 그룹화, timer 제어, 테스트 결과 검증, 통계 집계, 리포트 출력을 담당하는 메인 class.
* **`test_case_notimecheck`**: 특정 스코프 내에서 `test_case`의 시간 측정을 자동으로 일시정지/재개하는 RAII helper class.
* **`t_stream_binder<STREAM_T, BINDER>`**: stream buffer에 문자열 및 색상 바인더 데이터를 기입하는 template stream 가공 wrapper.

### 주요 method 분석

| class / method | 역할 및 기능 |
| --- | --- |
| **`test_case::begin`** | 새로운 test case 그룹을 시작하고 쓰레드별 타임스탬프 및 timer를 초기화함. |
| **`test_case::pause_time` / `resume_time`** | 쓰레드별 stopwatch를 일시정지하거나 다시 재개하여 정밀한 구간 시간을 측정함. |
| **`test_case::assert` / `vassert`** | 조건식(`bool`)의 참/거짓을 검증하여 테스트 결과를 기입함 (가변 인자 formatting 지원). |
| **`test_case::nassert` / `vnassert`** | 실패가 예상되는 조건(Negative Assertion)을 검증함. |
| **`test_case::test` / `vtest`** | `return_t` 오류 code를 직접 전달받아 `error_advisor` 기준 성공/실패 여부를 판단 및 기입함. |
| **`test_case::report`** | 전체 테스트 결과, 실패 내역, 상위 소요 시간(Top-N) 리포트를 출력 및 파일 저장함. |
| **`test_case::result`** | 전체 테스트 중 1개 이상의 실패(`_count_fail > 0`)가 존재하면 `internal_error`, 성공 시 `success` 반환함. |
| **`test_case::attach`** | logging 시스템(`logger`) 인스턴스를 binding하여 테스트 결과를 로거 stream으로 출력하도록 설정함. |

---

## 3. 핵심 내부 동작 원리 (Internal Architecture)

### 3.1. timer 측정 pipeline (Stopwatch Flow)

테스트 진행 시 쓰레드별 stopwatch가 작동하는 흐름

```
begin() / reset_time()
  │
  ├─► _time_flag_per_threads[tid] = true
  ├─► _timestamp_per_threads[tid] = monotonic_now()
  └─► _time_slice_per_threads[tid].clear()
  │
  ▼ [시간 측정 제외 구간 발생 시]
pause_time()   ──► diff(stamp, now) 계산 후 _time_slice에 추가, flag = false
resume_time()  ──► stamp = monotonic_now(), flag = true
  │
  ▼
test() / assert() / check_time()
  │
  ├─► (flag == true일 경우) 남은 diff 계산 후 _time_slice에 추가
  ├─► _time_slice 내 모든 구간 합산(time_sum) -> elapsed time 산출
  └─► unit test_item_t 생성 및 결과 집계 후 reset_time() 자동 호출

```

### 3.2. 결과 집계 및 카테고리화 (Category Pipeline)

`error_advisor`를 통해 결과 code가 자동으로 분류 및 통계 처리

```
[Result return_t] ──► advisor->categoryof(result)
                           │
                           ├─► success / expect_failure ──► _count_success 증가 (Cyan/Default)
                           ├─► severe                  ──► _count_fail 증가 (Red)
                           ├─► not_supported           ──► _count_not_supported 증가 (Cyan)
                           └─► trivial / warn / low    ──► _count_trivial 증가 (Yellow)

```

---

## 4. C++11 기반 사용 예시 (C++11 Example Usage)

`C++11` 규격

```cpp
#include <iostream>
#include <thread>
#include <hotplace/sdk/base/unittest/testcase.hpp>

// Dummy test functions
hotplace::return_t sample_success_function() {
    return hotplace::errorcode_t::success;
}

hotplace::return_t sample_fail_function() {
    return hotplace::errorcode_t::assert_failed;
}

void run_unit test_demo() {
    using namespace hotplace;

    test_case tc;

    // -------------------------------------------------------------
    // Group 1: Basic Assertions & Time Exclusion
    // -------------------------------------------------------------
    tc.begin("Basic Logic Test Group");

    // General boolean assertion
    tc.assert(1 + 1 == 2, __FUNCTION__, "Verify simple math addition");

    // Measure time excluding preparation block using RAII guard
    {
        test_case_notimecheck guard(tc);
        // Time consumed in this block will not be calculated
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Negative assertion (Expecting false)
    tc.nassert(1 == 2, __FUNCTION__, "Verify negative condition expectation");

    // -------------------------------------------------------------
    // Group 2: Errorcode Verification
    // -------------------------------------------------------------
    tc.begin("Return Code Test Group");

    return_t ret_success = sample_success_function();
    tc.test(ret_success, "sample_success_function", "Check success result code");

    // Intentionally testing a failing case
    return_t ret_fail = sample_fail_function();
    tc.test(ret_fail, "sample_fail_function", "Check intentional failure code");

    // -------------------------------------------------------------
    // Group 3: Reporting & Final Result
    // -------------------------------------------------------------
    // Display summary and top 5 execution time cases
    tc.report(5);

    if (tc.result() == errorcode_t::success) {
        std::cout << "All test cases passed successfully." << std::endl;
    } else {
        std::cout << "Some test cases failed. Please check report file." << std::endl;
    }
}

int main() {
    run_unit test_demo();
    return 0;
}
```

---

## 5. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`test_case` 및 관련 framework module 개발 관리 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| ~~**TODO-TC-01**~~ | `HIGH` | **`test_case::begin` 동시성 및 스레드 안전성 검증**<br><br>- `topic` formatting 스레드 격리 및 `_testcase_per_threads` guard 범위 보호 확인 완료 | `No change required` | `testcase.cpp` |
| **TODO-TC-02** | `MEDIUM` | **JSON / XML 포맷의 리포트 파일 익스포트 option 추가**<br>- CI/CD pipeline(Jenkins, GitHub Actions) 연동을 위한 규격 포맷 출력 mechanism 구현 | `To Do` | `report()` 함수 확장 |

---
