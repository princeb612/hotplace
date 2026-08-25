# `payload` 및 `payload_member` - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

`payload` module은 네트워크 protocol packet(TLS, DTLS, QUIC 등)의 직렬화(Serialization/Write) 및 역직렬화(Deserialization/Read/Parse)를 유연하게 처리하기 위해 설계된 C++11 builder pattern 기반 데이터 parsing framework.

### 주요 특징

1. **유연한 field metadata 구성 (`payload_member`)**:
* 정수형(int8~uint128), 엔디안(Big/Little Endian), 가변 길이 binary, 문자열, Bignumber, Encoded 타입 자동 추상화.
2. **동적 field 참조 연산 (`set_reference_value`)**:
* 특정 field의 길이가 이전 field의 값에 의존하는 구조(예: Length Field -> Payload)를 자동 binding 처리.
3. **조건부 field 및 그룹 제어 (`set_group`, `set_condition`)**:
* 특정 flag나 header 값에 따라 하위 그룹을 활성화/비활성화(`set_group`)하거나 후킹 callback(`set_condition`)을 실행하여 동적 parsing 지원.
4. **추측성 가변 parsing (Heuristic Reading)**:
* 가변 길이를 알 수 없는 항목(`list_size_unknown`)이 존재하는 경우, 전체 buffer 크기 대비 잔여 영역을 추론하여 slicing parsing 수행.

---

## 2. 핵심 class 및 API 구조 분석 (API Reference)

### 주요 class 역할

* **`payload_member`**: packet 내부의 단일 데이터 항목 단위. 엔디안 변환, 메모리 할당, reference 연산 담당.
* **`payload_encoded`**: 가변 길이 표현 방식(예: QUIC variable-length integer 등) interface 규격.
* **`payload`**: 여러 `payload_member`를 chaining으로 등록하여 binary 데이터를 읽고 쓰거나 조건별 해석을 총괄하는 container.

### 주요 method 분석

| class / method | 역할 및 기능 |
| --- | --- |
| **`payload::operator<<`** | `unique_ptr` 또는 `t_pointer_proxy` 기반으로 field를 직관적으로 chaining 추가. |
| **`set_reference_value(name, ref, mult)`** | `name` field의 크기를 `ref` field의 값 $\times$ `mult` 크기로 동적 지정. |
| **`set_condition(name, hook)`** | `name` field가 parsing된 후 호출할 callback 함수 등록 (그룹 조건 동적 변경 가능). |
| **`read(ptr, size, pos)`** | binary stream에서 등록된 member 순서대로 데이터를 읽어 parsing 수행. |
| **`write(bin, groups)`** | 현재 구성된 member들 중 활성화된 그룹의 데이터를 binary stream으로 직렬화 출력. |
| **`t_value_of<T>(name)`** | parsing된 member의 값을 지정한 타입 $T$로 안전하게 추출. |

---

## 3. C++11 기반 실습 code (C++11 Example Usage)

`C++11` 규격 준수

```cpp
#include <iostream>
#include <hotplace/sdk/io/basic/payload.hpp>

int main() {
    using namespace hotplace::io;

    // 1. Construct payload structure
    // Data Structure: Header (1 byte) | Length (2 bytes, BigEndian) | Payload (Dynamic) | Padding (Optional)
    payload pl;

    pl << new payload_member(uint8(0), "hdr")
       << new payload_member(uint16(0), true, "len")
       << new payload_member(binary_t(), "data")
       << new payload_member(binary_t(), "pad", "padding_group");

    // 2. Set dynamic reference & conditional group hook
    pl.set_reference_value("data", "len"); // "data" size refers to "len" value

    pl.set_condition("hdr", [](payload* p_pl, payload_member* item) {
        // If high bit of hdr is set, enable padding group
        uint8 hdr_val = p_pl->t_value_of<uint8>(item);
        bool use_padding = (hdr_val & 0x80) != 0;
        p_pl->set_group("padding_group", use_padding);
    });

    // 3. Test parsing with binary stream
    // Header: 0x80 (Padding enabled)
    // Len: 0x00, 0x04 (4 bytes)
    // Data: 'T', 'E', 'S', 'T'
    // Pad: 'P', 'A', 'D'
    binary_t stream = {0x80, 0x00, 0x04, 'T', 'E', 'S', 'T', 'P', 'A', 'D'};
    size_t pos = 0;

    if (pl.read(stream.data(), stream.size(), pos) == errorcode_t::success) {
        uint8 hdr = pl.t_value_of<uint8>("hdr");
        uint16 len = pl.t_value_of<uint16>("len");

        binary_t data_bin;
        pl.get_binary("data", data_bin);

        std::cout << "[Parsing Success]\n";
        std::cout << "Header: 0x" << std::hex << (int)hdr << std::dec << "\n";
        std::cout << "Length: " << len << "\n";
        std::cout << "Data Size: " << data_bin.size() << "\n";
        std::cout << "Read Offset: " << pos << " bytes\n";
    }

    return 0;
}

```

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

`payload` module의 안정성 확보 및 성능 향상을 위한 번호 체계 기반 TODO 항목

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-PL-01** | `HIGH` | **`read()` 함수 내 `list_size_unknown` 예외 처리 강화**<br>- 미지 크기 member가 2개 이상일 때 예외 반환 처리 검증 및 가변 길이 바운드 검사 보완 | `In Progress` | `read()` 2차 패스 logic |
| **TODO-PL-02** | `HIGH` | **`payload_member` 메모리 생성/소멸 누수 검증**<br>- RAW pointer 전달 방식 대신 `std::unique_ptr` 소유권 이전 구조로 통일 | `To Do` | `operator<<` 정리 |
| **TODO-PL-03** | `MEDIUM` | **`doread` 내 엔디안 변환 유틸리티 최적화**<br>- `ntoh16`/`ntoh32`/`ntoh64` 외 24비트, 48비트 mapping 시 바이트 오프셋 경계 검사 강화 | `To Do` | `doread()` 수치 변환 |
| **TODO-PL-04** | `MEDIUM` | **`set_condition` 멀티 훅(Hook) 순서 보장 검토**<br>- `std::multimap` 기반 callback 저장 시 동일 키 등록 callback 실행 순서 신뢰성 확보 | `In Progress` | `_cond_map` 구조 |
| **TODO-PL-05** | `LOW` | **`payload::write` 시 그룹 filtering 성능 개선**<br>- `std::set<std::string>` 조회 overhead를 줄이기 위한 hash/flag 기반 그룹 식별자 전환 검토 | `To Do` | 직렬화 성능 향상 |

---
