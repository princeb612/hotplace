# `t_range_set` & `t_interval` - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

`range_set.hpp` module은 QUIC ACK Ranges, 메모리 세그먼트 관리, 수치 범위 연산 등에서 불연속적이거나 겹치는 구간(Intervals)들을 효율적으로 병합(Merge), 차집합(Subtract), 교집합(Intersect), 합집합(Union) 연산하기 위해 설계된 C++11 template 기반 범위 집합 module

### 주요 특징

1. **타입별 맞춤 병합 특성화 (`range_traits`)**:
* 정수형(Discrete): 연속된 값(`current.end + 1 >= next.begin`)을 자동으로 인접 병합 처리.
* 실수형(Continuous/Floating Point) 및 커스텀 타입: 열린 구간(`open` / `( )`)과 닫힌 구간(`closed` / `[ ]`) 경계 조건 판단을 통한 정밀 병합 지원.

2. **무한대 범위 표현 (`t_range_value`)**:
* `minvalue`($-\infty$), `maxvalue`($+\infty$) 지원을 통해 무한 범위 연산 가능.

3. **집합 연산 및 Inversion 개념 지원**:
* 합집합(`union_with`), 차집합(`erase_from`), 교집합(`intersect_with`) 연산 제공.
* `invert()` switch를 통한 여집합(All-Except / Inverted Range) 조건 표현 가능.

4. **thread 안전성 (Thread Safety)**:
* 내부적으로 `critical_section` 및 `critical_section_guard`를 활용하여 동시성 환경에서의 데이터 일관성 보장.

---

## 2. 핵심 class 및 API 구조 분석 (API Reference)

### 주요 열거형 및 구조체

```cpp
enum class range_type_t : int8 { minvalue = -1, value = 0, maxvalue = 1 };
enum class range_flag_t : uint8 { open = 0, closed = 1 };

template <typename T>
struct t_interval {
    T begin;
    T end;
    range_flag_t begin_flag;
    range_flag_t end_flag;
};
```

### 주요 method 분석

| class / method | 역할 및 기능 |
| --- | --- |
| **`t_range_set<T>`** | 범위 구간 집합 관리 class. |
| `add(start, end)` | 시작과 끝 지점을 지정하여 범위 추가. (`t_interval`, `t_range_set` 지원). |
| `subtract(start, end)` | 특정 구간을 차집합 연산하여 제거. (경계 flag 자동 재조정). |
| `intersect(other)` | 다른 `t_range_set`과의 공통 교집합 추출. |
| `merge()` | 내부 구간들을 정렬 후 중복/접합 구간을 하나로 완전 병합하여 반환. |
| `has(value)` / `has(interval)` | 값 또는 특정 구간이 포함되어 있는지 여부 검증. |
| `union_with(other)` | Inversion 상태를 고려한 집합 합병 연산. |
| `erase_from(other)` | Inversion 상태를 고려한 집합 차집합 연산. |

---

## 3. C++11 기반 실습 code (C++11 Example Usage)

`C++11` 규격 준수

```cpp
#include <iostream>
#include <hotplace/sdk/base/nostd/range_set.hpp>

int main() {
    using namespace hotplace;

    // 1. Integer Range Set Example (Discrete values)
    t_range_set<uint64> ack_ranges;

    // Add overlapping or consecutive packet numbers
    ack_ranges.add(1, 5)
              .add(6, 10)   // Automatically merges with [1, 5] -> [1, 10]
              .add(14, 18)
              .add(21);     // Single point range [21, 21]

    std::cout << "[ACK Ranges Merge Result]\n";
    auto merged = ack_ranges.merge();
    for (const auto& item : merged) {
        std::cout << "Range: [" << item.begin << ", " << item.end << "]\n";
    }

    // 2. Floating Point & Infinite Range Example
    using fp_range_set = t_range_set<t_range_value<float>>;
    using fp_interval  = t_interval<t_range_value<float>>;

    fp_range_set float_ranges;

    // Add [-inf, -1.0] and [1.0, 4.0], then subtract [1.5, 3.5]
    float_ranges.add(range_type_t::minvalue, -1.0f)
                .add(1.0f, 4.0f)
                .subtract(1.5f, 3.5f);

    std::cout << "\n[Float Range Subtract Result]\n";
    float_ranges.for_each2([](const fp_interval& item) {
        char left_bracket  = (item.begin_flag == range_flag_t::closed) ? '[' : '(';
        char right_bracket = (item.end_flag == range_flag_t::closed) ? ']' : ')';

        std::cout << "Range: " << left_bracket;
        if (item.begin.type == range_type_t::minvalue) std::cout << "-INF";
        else std::cout << item.begin.value;

        std::cout << ", ";

        if (item.end.type == range_type_t::maxvalue) std::cout << "+INF";
        else std::cout << item.end.value;

        std::cout << right_bracket << "\n";
    });

    // Point check
    std::cout << "\nContains 1.2f: " << (float_ranges.has(1.2f) ? "true" : "false") << "\n";
    std::cout << "Contains 2.0f: " << (float_ranges.has(2.0f) ? "true" : "false") << "\n";

    return 0;
}
```

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`range_set.hpp` module의 고도화 및 유지보수를 위한 번호 체계 기반 TODO 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-RS-01** | `HIGH` | **`merge_internal` 정렬 및 병합 algorithm tunning**<br>- 이미 정렬된 상태이거나 소량 데이터 삽입 시 `std::sort` 전체 호출 대신 삽입 정렬(Insertion Sort) 기법 적용 검토 | `To Do` | `merge_internal()` 성능 개선 |
| **TODO-RS-02** | `HIGH` | **`subtract` 및 `intersect` 연산 시 `critical_section` 락 범위 최소화**<br>- 임시 객체 생성 시 락 조기 해제(Fine-grained Locking) 기법 적용 검토 | `In Progress` | thread 경합 줄임 |
| **TODO-RS-03** | `MEDIUM` | **C++11 `std::initializer_list` 지원**<br>- `add({ {1, 5}, {6, 10} })` 형태의 초기화 list 생성자 및 삽입 API 추가 | `To Do` | 편의성 확장 |
| **TODO-RS-04** | `MEDIUM` | **Inverted Set (`_invert`) 대칭성 관련 포괄적 unit test 작성**<br>- `union_with`, `erase_from`, `intersect_with` 간 4가지 드모르간 조합 조건 테스트 보완 | `In Progress` | `_test_case` 검증 |
| **TODO-RS-05** | `LOW` | **`t_range_value` 비교 연산자 C++11 template 정리**<br>- 타입 변환 시 발생 가능한 컴파일 경고 해결 및 주석 영문화 작성 완료 | `To Do` | Header 문서화 |

---
