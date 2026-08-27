# `basic_stream` 및 `bufferio` framework - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

`basic_stream` module은 내부 데이터 chunk(Chunk) 관리 layer인 `bufferio`와 타입 처리 layer인 `traits_printf`를 결합하여 만든 동적 stream buffer class
C++ 표준 `std::stringstream`의 입출력 가용성과 C style buffer 처리의 메모리/속도 효율성을 동시에 제공

### 주요 특징

1. **분할 chunk 기반 동적 메모리 관리 (`bufferio`)**:
  * chunk list(`bufferin_queue_t`) 방식으로 데이터를 할당하여 잦은 `realloc` overhead 최소화.
  * 읽기 요청(`c_str()`, `data()`) 시 단일 연통 메모리로 자동 재구성(Flattening).
2. **타입 trait 기반 Printf pipeline (`printf_traits`)**:
  * 정수, 열거형(enum), 실수 타입을 metaprogramming으로 자동 추상화하여 format string(`%d`, `%u`, `%f` 등) mapping.
  * 복잡한 SFINAE 조건문을 `printf_traits`로 단일화하여 유지보수성 향상.
3. **강한 예외 보장 (Strong Exception Guarantee)**:
  * 복사 대입 연산자(`operator=`)에 Copy-and-Swap 관용구 적용.
4. **stream 커스텀 확장성 (`encoder_stream_traits`)**:
  * `custom::encoder_stream_traits<basic_stream>` 특수화를 통해 외부 encoder/decoder algorithm과 직접 결합 가능.

---

## 2. 핵심 class 및 구조 분석 (API Reference)

### 주요 구성요소

* **`bufferio`**: 메모리 chunk 할당(`extend`), 병합, C-string 변환, slicing(`cut`), 삽입(`insert`) 등 low-level 동적 buffer 조작 담당.
* **`printf_traits`**: C++ 타입을 C-Style `printf` 서식 지정자 및 캐스팅 타입으로 자동 변환해 주는 metaprogramming trait.
* **`basic_stream`**: `stream_t` interface를 구현하며 연산자 overloading(`<<`, `+=`, `==`) 및 C++ style stream interface 제공.

### 주요 method 분석

| class / method | 역할 및 기능 |
| --- | --- |
| **`basic_stream::operator<<`** | 원시 타입, `std::string`, `binary_t`, `bignumber`, `variant` 등을 stream에 순차 직렬화. |
| **`basic_stream::printf` / `println`** | 가변 인자를 받아 내부 `bufferio::vprintf`를 호출해 데이터 추가. |
| **`basic_stream::vaprintf`** | 커스텀 `valist` 객체와 포맷 template(`{1}`, `{2:04x}` 등)을 조합하여 가변 formatting 출력. |
| **`basic_stream::cut(pos, len)`** | 지정한 위치부터 `len` 크기만큼 buffer chunk를 재조정하여 삭제. |
| **`basic_stream::insert(pos, ptr, len)`** | 지정한 위치에 신규 메모리 chunk를 분할 삽입. |
| **`basic_stream::resize(s)`** | buffer 크기를 변경. 줄어들면 `cut`, 늘어나면 `fill(0)`을 수행. |
---

## 3. 핵심 내부 동작 원리 (Internal Architecture)

### 3.1. 타입 trait mapping pipeline (`printf_traits`)

가변 타입의 `operator<<` 호출 시, `printf_traits`가 다음 과정을 통해 C style `printf` 서식을 도출함:

```
[Input Type T]
      │
      ▼
std::decay<T>::type ──► Enum 여부 검사 (integral_type)
      │
      ▼
크기(sizeof) & Signed 여부 판별
      │
      ▼
cast_type (int / unsigned int / long long 등) 선정
      │
      ▼
format_specifier_traits<BT, final_type>::spec ("%d", "%u", "%lld" 등) 추출
```

* **성능 최적화**: 단일 `char` 및 `const char*`는 `printf` 서식 parsing overhead를 피하기 위해 `bufferio::write`로 직접 메모리 복사 수행.

### 3.2. 메모리 chunk 병합 (Buffer Flattening)

`bufferio`는 내부적으로 `std::list<bufferio_t*>` 구조를 사용하여 쓰기 작업 시 block 단위로 메모리를 할당함.

```
[Write Operations]
Queue: [Block 1 (1024b)] -> [Block 2 (1024b)] -> [Block 3 (256b)]

[c_str() / data() Call]
1. 연속된 단일 block 할당 (Total Size)
2. Queue의 모든 block 데이터 복사 & NUL padding 붙임
3. 기존 Queue block 해제 후 단일 block으로 대체
Result: [Single Contiguous Block (2304b)]

```

---

## 4. C++11 기반 사용 예시 (C++11 Example Usage)

`C++11` 규격

```cpp
#include <iostream>
#include <hotplace/sdk/base/stream/basic_stream.hpp>

void run_basic_stream_sample() {
    using namespace hotplace;

    // -------------------------------------------------------------
    // Demo 1: Operator Insertion & Basic Data Append
    // -------------------------------------------------------------
    basic_stream bs;
    bs << "Header: " << 100 << ", Flag: " << true << ", Value: " << 3.14159;
    bs.println(" [END]");

    std::cout << "[Demo 1 Output]\n" << bs.c_str();

    // -------------------------------------------------------------
    // Demo 2: String Formatting with vaprintf (valist)
    // -------------------------------------------------------------
    basic_stream bs_fmt;
    valist va;
    va << 256 << "hello world" << 3.141592;

    // Format syntax: {n}, {n:04x}, {n:-15s}, {n:lf}
    bs_fmt.vaprintf("HEX: {1:04x}, STR: {2:-15s}, FLOAT: {3:lg}", va);

    std::cout << "\n[Demo 2 Output]\n" << bs_fmt.c_str() << "\n";

    // -------------------------------------------------------------
    // Demo 3: Buffer Slicing and Dynamic Cut/Insert
    // -------------------------------------------------------------
    basic_stream bs_buf("0123456789");
    bs_buf.cut(2, 4); // Remove "2345" -> "016789"
    bs_buf.insert(2, "ABCD", 4); // Insert "ABCD" at pos 2 -> "01ABCD6789"

    std::cout << "\n[Demo 3 Output]\n" << bs_buf.c_str() << "\n";
}

int main() {
    run_basic_stream_sample();
    return 0;
}
```

---

## 5. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`basic_stream` 및 `bufferio` pipeline 관련 개발 관리 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-BS-01** | `HIGH` | **`bufferio::insert` 락 범위 최적화**<br>- chunk 분할 및 메모리 할당 중 예외 발생 시 safeguard 및 락 경합 범위 축소 | `Postponed` | `bufferio.cpp`<br> |
| ~~**TODO-BS-02**~~ | `HIGH` | **128-bit 정수형 포맷 서식 지정자 cross-platform 검증**<br>- `__SIZEOF_INT128__` 지원 환경에서 `%I128i` / `%I128u` 서식 문자열 호환성 검토 | `No change required` | 기존 테스트 케이스 `testcase_stream.cpp` |
| ~~**TODO-BS-03**~~ | `MEDIUM` | **`basic_stream::fill` 대용량 padding 속도 향상**<br>- Chunk size (256 bytes) 기반 `memset` 할당 loop의 block 단위 우회 최적화 | `No change required` | `basic_stream.cpp`<br> |
| **TODO-BS-04** | `MEDIUM` | **`std::string_view` (C++17 대비) overloading interface 설계**<br>- C++11 규격 유지하되, 뷰 타입 호환 wrapper layer 사전 정의 | `To Do` | `operator<<` 확장 |
| **TODO-BS-05** | `LOW` | **Wide String 오버헤드 절감을 위한 플랫폼 경계 재정의**<br><br>- Linux: `char*` (UTF-8) 중심 처리로 4바이트 `wchar_t` 할당 축소<br><br>- Windows: Win32 API 호출부(`ansi2wide`/`wide2ansi`) 영역으로 `wchar_t` 변환 격리 | `To Do` | `unicode/` & `windows/` <br> |

* TODO-BS-05 : 크로스 플랫폼 추상화 방향 재정의
  * **Linux / POSIX**:
    * `char*` / `std::string` (UTF-8)을 기본 및 유일한 내부 스트림 버퍼 타입으로 사용.
    * `wchar_t` 관련 함수(`bufferio_wcs`, `printf_wcs`)는 POSIX 환경에서 호출 자체를 경고 처리하거나 단순 UTF-8 내보내기/변환 래퍼로 최소화.
  * **Windows**:
    * Win32 API(`W` 버전에 해당하는 System Call) 연동을 위해 **UTF-16 LE(`wchar_t`, 2bytes)** 변환이 필요한 접점(`windows/ansi2wide.cpp`, `wide2ansi.cpp`) 내부에서만 조건부 컴파일(`_WIN32`)로 한정 처리.
    * Windows 역사의 유산: UCS-2와 UTF-16
      * **과거 Windows NT 시절**: 유니코드 초기 규격(16비트로 모든 문자를 표현 가능하다고 믿었던 시절)의 **UCS-2(Fixed 2-byte)** 방식을 OS API의 기본 문자열(`wchar_t`) 체계로 채택했습니다. 이때부터 Windows는 이를 단순히 "UNICODE"라고 불렀습니다.
      * **이후 확장 (UTF-16)**: 유니코드 범위가 확장되면서 2바이트만으로 모든 문자를 표현할 수 없게 되자, 2바이트~4바이트 가변 길이 인코딩 방식인 **UTF-16** 기법(서로게이트 페어, Surrogate Pair)이 도입되었습니다.
      * **현재의 Windows API**: 내부적으로는 **UTF-16 Little Endian** 인코딩을 기반으로 동작하지만, C/C++ Header 및 Win32 API 매크로 명칭(`UNICODE`, `WCHAR`, `LPCWSTR`)에 과거의 명칭이 그대로 남아 있어 'Windows 유니코드'와 'UTF-16'이 혼용되곤 합니다.
    * POSIX(Linux) `wchar_t`와의 결정적 차이
      * **Windows**: `wchar_t`를 2바이트(UTF-16 LE)로 정의하며, Win32 API(`CreateWindowW`, `CreateFileW` 등)의 네이티브 인코딩으로 사용합니다.
      * **Linux/POSIX**: `wchar_t`를 4바이트(UTF-32/UCS-4)로 정의하며, OS 기본 시스템 콜과 파일 시스템 표준은 UTF-8(`char*`)을 사용합니다.

---
