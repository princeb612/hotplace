# `logger` framework - published by Gemini

## 1. 개요 및 설계 구조 (Overview & Architecture)

`logger` module은 builder pattern(Builder Pattern)과 쓰레드별 컨text(Thread-Local Context) 관리를 기반으로 구축된 멀티쓰레드 환경 지원 logging 시스템
백그라운드 소비 쓰레드(Consumer Thread)를 이용한 지연 flush(Delayed Flush) mechanism을 적용하여 I/O 병목을 최소화

### 주요 특징

1. **builder pattern 기반 객체 생성 (`logger_builder`)**:
* `logger_builder`를 통해 표준 출력, 파일 저장, flush 주기/크기, 시간 포맷, 테스트케이스 binding 등을 chaining 형태로 설정 후 빌드함.
2. **쓰레드별 데이터 격리 (`logger_item`)**:
* 쓰레드 ID(`tid`)별로 독립된 `basic_stream` buffer를 mapping하여 쓰레드 간 동기화 overhead 최소화.
* reference counting(`t_shared_reference`) 기반으로 안전한 메모리 생명주기 관리함.
3. **지연 쓰기 및 소비자 쓰레드 (Deferred Flushing & Consumer Thread)**:
* 백그라운드 쓰레드가 일정 주기(`logger_interval`)마다 파일 buffer(`delayed`)의 크기 및 시간을 감지해 일괄 flush 수행.
4. **ANSI 콘솔 색상 지원 (`console_color`)**:
* style, 전경색, 배경색을 지정하여 terminal 로그 가독성 향상.
5. **메모리 dump 기능 (`dump`, `hdump`)**:
* binary 데이터 및 메모리 주소를 헥사(Hex) dump 형태로 직렬화 출력함.

---

## 2. 핵심 class 및 구조 분석 (API Reference)

### 주요 구성요소

* **`logger_builder`**: 로거의 주요 설정값(콘솔, 파일, flush 조건 등)을 조합하고 ASCII 아트 배너 출력 후 `logger` instance 생성함.
* **`logger_item`**: 쓰레드별로 할당되는 구조체로, 실시간 출력용 buffer(`bs`), 파일 flush용 지연 buffer(`delayed`), 타임스탬프 및 참조 카운트 보유함.
* **`logger`**: thread 세이프 logging, 레벨 filtering, 메모리 dump, ANSI 컬러 출력 등 핵심 interface 제공함.

### 주요 method 분석

| class / method | 역할 및 기능 |
| --- | --- |
| **`logger_builder::set_logfile`** | 파일 logging 활성화 및 출력 로그 파일 경로 지정함. |
| **`logger::writeln` / `write`** | 포맷 문자열(`vprintf`), `std::string`, `basic_stream`, `stream_t*`, lambda 함수 형태 데이터를 출력 buffer에 기입함. |
| **`logger::consoleln`** | 콘솔 전용 출력을 수행함. |
| **`logger::dump` / `hdump`** | 메모리 주소 및 binary 데이터를 Hex dump 형태로 출력 buffer에 기록함 (header 지정 가능). |
| **`logger::flush`** | 지연 buffer(`delayed`)에 적재된 로그를 체크하여 파일로 한 번에 쓰기 수행함. |
| **`logger::setcolor` / `colorln`** | 콘솔 style 및 색상을 설정하여 컬러 로그 출력함. |

---

## 3. 핵심 내부 동작 원리 (Internal Architecture)

### 3.1. 쓰레드별 buffer 격리 (Thread-Local Context Flow)

로그 요청 시 쓰레드 ID 기반으로 buffer를 격리하여 동시 쓰기 시 경합 최소화함:

```
[Thread A] ──► get_context() ──► TID A 검색 ──► logger_item A (bs / delayed)
                                                      │
                                                      ▼
                                            basic_stream 데이터 기록
                                                      │
                                                      ▼
                                         touch() 호출 -> 지연 buffer 이관

```

### 3.2. 비동기 flush pipeline (Async Flushing Pipeline)

백그라운드 쓰레드 `consumer`가 주기적으로 실행되며 `flush(true)` 호출함:

```
[Consumer Thread]
      │
      ▼ (interval 마다 대기)
  flush(check = true)
      │
      ├─► 조건 검사: (현재 시간 - timestamp >= flush_time) OR (bs.size() >= flush_size)
      │
      └─► 조건 충족 시: std::ofstream (ios::app)으로 파일에 일괄 기입 후 bs.clear()

```

---

## 4. C++11 기반 사용 예시 (C++11 Example Usage)

`C++11` 규격

```cpp
#include <iostream>
#include <hotplace/sdk/base/unittest/logger.hpp>

void run_logger_sample() {
    using namespace hotplace;

    // -------------------------------------------------------------
    // Demo 1: Build Logger Instance
    // -------------------------------------------------------------
    logger_builder builder;
    builder.set(logger_t::logger_stdout, 1)
           .set(logger_t::logger_interval, 200)
           .set(logger_t::logger_flush_time, 5)
           .set_timeformat("Y-M-D h:m:s.f ")
           .set_logfile("sample.log");

    // Create shared logger instance
    t_shared_instance<logger> log_inst;
    log_inst.make_share(builder.build());

    // -------------------------------------------------------------
    // Demo 2: Basic Writing & Level Filtering
    // -------------------------------------------------------------
    log_inst->set_loglevel(loglevel_t::loglevel_trace);
    log_inst->writeln("Basic log message with format: %d", 1234);
    log_inst->writeln(loglevel_t::loglevel_debug, "Debug message level check");

    // -------------------------------------------------------------
    // Demo 3: Console Color Logging
    // -------------------------------------------------------------
    log_inst->setcolor(console_style_t::bold, console_color_t::fgcyan, console_color_t::black);
    log_inst->colorln("Colored log output via logger");

    // -------------------------------------------------------------
    // Demo 4: Hex Memory Dump
    // -------------------------------------------------------------
    uint8_t buffer[16] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x0A, 0x0D, 0xFF};
    log_inst->hdump("Memory Dump Header", buffer, sizeof(buffer));

    // Force flush
    log_inst->flush();
}

int main() {
    run_logger_sample();
    return 0;
}

```

---

## 5. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`logger` module 관련 개발 관리 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-BS-01** | `HIGH` | **`bufferio::insert` 락 범위 최적화**<br>- chunk 분할 및 메모리 할당 중 예외 발생 시 safeguard 및 락 경합 범위 축소 | `In Progress` | `bufferio.cpp`<br> |
| **TODO-BS-02** | `HIGH` | **128-bit 정수형 포맷 서식 지정자 cross-platform 검증**<br>- `__SIZEOF_INT128__` 지원 환경에서 `%I128i` / `%I128u` 서식 문자열 호환성 검토 | `To Do` | `traits_printf.hpp`<br> |
| **TODO-BS-03** | `MEDIUM` | **`basic_stream::fill` 대용량 padding 속도 향상**<br>- Chunk size (256 bytes) 기반 `memset` 할당 loop의 block 단위 우회 최적화 | `Completed` | `basic_stream.cpp`<br> |
| **TODO-BS-04** | `MEDIUM` | **`std::string_view` (C++17 대비) overloading interface 설계**<br>- C++11 규격 유지하되, 뷰 타입 호환 wrapper layer 사전 정의 | `To Do` | `operator<<` 확장 |
| **TODO-BS-05** | `LOW` | **Wide String (`wchar_t`) 지원 macro 정리**<br>- `_WIN32`/`_WIN64` 전용 코딩 영역 분리 및 POSIX 환경 interface 통합 | `To Do` | platform 추상화 |
| **TODO-LOG-01** | `HIGH` | **로그 파일 로테이션 (`logger_rotate_size`, `logger_max_file`) 구현**<br>- 파일 크기 초과 시 파일 분할 및 최대 개수 유지 logic 추가 | `To Do` | `logger.cpp` (`flush` 확장) |
| **TODO-LOG-02** | `MEDIUM` | **종료된 쓰레드 컨text(`_logger_stream_map`) 정리 mechanism 구축**<br>- 쓰레드 종료 시 자원 누수를 막기 위한 가비지 수집 logic 마련 | `To Do` | `logger.cpp`<br> |

---
