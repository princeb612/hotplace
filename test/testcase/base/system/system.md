## 시스템 및 수치 연산 - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 대용량 정수, floating point(IEEE 754), 엔디안(Endianness), 날짜/시간 및 동기화 thread 연산 등 기본 시스템/수치 처리 module.
* **주요 기능**:
  * **대용량 정수 연산**: BigNumber parsing, 기본 사칙연산 및 비트 연산 처리 (`testcase_bignumber.cpp`).
  * **floating point 및 IEEE 754 제어**: floating point 정밀도, 비트 레이아웃 parsing 및 IEEE 754 규격 검증 (`testcase_floatingpoint.cpp`, `testcase_ieee754.cpp`).
  * **엔디안 및 시스템 resource 제어**: Big/Little Endian 변환 및 메모리 Capacity / Shared 자원 관리 (`testcase_endian.cpp`, `testcase_capacity.cpp`, `testcase_shared.cpp`).
  * **멀티thread 동기화**: Signal-Wait pattern 기반 thread 동기화 제어 (`testcase_signalwait_threads.cpp`).
  * **YAML 기반 test vector 검증**: BigNumber, Capacity, FloatingPoint 연산 검증용 테스트 데이터 연동 (`testvector_*.yml`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **BigNumber 연산 및 overflow 처리 (`testcase_bignumber.cpp`, `testvector_bignumber.cpp`)**:
  * 가변 길이 배열 기반 임의 정밀도(Arbitrary-precision) 정수 연산 algorithm.
  * YAML 기반 표준 test vector와 비교를 통한 연산 정확성 검증.
* **IEEE 754 floating point 및 엔디안 parsing (`testcase_ieee754.cpp`, `testcase_endian.cpp`)**:
  * 부호(Sign), 지수부(Exponent), 가수부(Mantissa) 비트 추출 및 NaN/Infinity 예외 처리.
  * 바이트 오더(Byte Order) 변환 연산(Big-Endian <-> Little-Endian).
* **멀티thread 동기화 및 자원 관리 (`testcase_signalwait_threads.cpp`, `testcase_shared.cpp`)**:
  * C++11 `std::condition_variable` 및 `std::mutex` 기반 Signal-Wait 동기화 pattern 구현.
  * Shared Resource 접근 시 Race Condition 방지 및 메모리 Capacity 확장 연산.
* **날짜/시간 및 buffer 용량 연산 (`testcase_datetime.cpp`, `testcase_capacity.cpp`)**:
  * UTC 및 Local Time 타임스탬프 parsing 및 formatting.
  * 동적 buffer Reallocation 기준 및 Capacity 할당 mechanism 검증.

---

### 3. 핵심 동작 mechanism

* **BigNumber 사칙연산 및 검증 (`testcase_bignumber.cpp`)**:
  * 자릿수 단위 Carry/Borrow 처리 기반 계산 수행 후 test vector 데이터와 matching 연산.
* **IEEE 754 Bit Manipulation (`testcase_ieee754.cpp`)**:
  * `union` 또는 `reinterpret_cast`를 활용한 float/double 비트 레벨 분석 및 IEEE 754 규격 연산.
* **Thread Signal/Wait 동기화 (`testcase_signalwait_threads.cpp`)**:
  * 대기 thread가 조건을 충족할 때까지 Wait 상태 유지 후, 작업 thread의 Notification 수신 시 깨어나는 동기화 handling.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **SYSTEM1** | `testcase_bignumber.cpp` 내 대용량 나눗셈 및 moduler 연산 예외 처리 강화 | High | 미진행 |
| **SYSTEM2** | `testcase_signalwait_threads.cpp` Spurious Wakeup 방지용 Predicate 조건 검증 보완 | High | 미진행 |
| **SYSTEM3** | `testcase_ieee754.cpp` Denormalized Number(비정규화 수) 처리 시 언더플로우 검증 | Medium | 미진행 |
| **SYSTEM4** | `testcase_endian.cpp` 64비트 정수형 byte swapping 성능 최적화 | Medium | 미진행 |
| **SYSTEM5** | `testcase_datetime.cpp` 타임존(Timezone) 변환 시 윤초(Leap Second) 예외 케이스 추가 | Low | 미진행 |
