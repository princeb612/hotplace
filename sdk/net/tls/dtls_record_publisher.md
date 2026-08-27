# DTLS Record Fragmentation & Stream Splitter Engine Module - published by Gemini

## 1. 개요 및 설계 목적 (Overview & Design Pattern)

DTLS(Datagram Transport Layer Security) 프로토콜 기반 네트워크 통신 환경에서 핸드셰이크 메시지 및 데이터 record를 패킷 최대 전송 단위(PMTU / Segment Size) 및 프래그먼트 크기(Fragment Size) 제한에 맞춰 컴파일 타임 및 런타임 제약 조건을 준수하여 분할 및 재조립(Segmentation & Fragmentation)을 수행하는 **DTLS Record Publisher & Stream Splitter Engine**

### 주요 특징

* **DTLS Fragmentation 지원**: DTLS 메시지 시퀀스(`hsseq`) 관리 및 핸드셰이크 헤더를 트리밍하여 MTU 이하 크기의 단편화된 핸드셰이크 패킷(`dtls_handshake_fragmented`)으로 세그먼테이션 수행.

* **C++11 Runtime & C++14 Compile-time 지원**:
  * **Runtime**: C++11 규격 기반 실행 및 lambda 함수(`std::function`), 스마트 포인터 및 STL 컨테이너 중심의 메모리 및 리소스 관리.
  * **Compile-time**: C++14 `constexpr` 제약 조건 완화 및 표준 템플릿 메타프로그래밍 유틸리티(`std::make_index_sequence`, `std::index_sequence`)를 활용한 템플릿 기반 파이프라인 확장 지원.
* **RAII 패턴 및 템플릿 처리**: 메모리 세척, 객체 생성/소멸 관리, 참조 카운팅(`addref`/`release`)을 적용하여 리소스 누수 차단.

---

## 2. 핵심 class, struct 및 API 구조 분석 (API Reference)

### 1) `splitter.hpp` & `dtls_record_publisher.hpp` (Core Engine & Declarations)

스트림 및 핸드셰이크 단편화를 관리하는 템플릿 클래스 `splitter<T>`와 DTLS record publisher 선언부

```cpp
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <list>
#include <functional>
#include <cstdint>

namespace hotplace {
namespace net {

// Descriptor struct for DTLS handshake fragmentation metadata
struct spl_desc {
    tls_handshake_type_t hstype;
    uint16 hsseq;
};

// Generic stream splitter template class
template <typename Descriptor>
class splitter {
public:
    splitter() : segment_size_(1024) {}
    ~splitter() = default;

    void set_segment_size(uint16_t size) { segment_size_ = size; }
    uint16_t get_segment_size() const { return segment_size_; }

    void add(binary_t&& data, Descriptor&& desc) {
        data_list_.push_back(std::move(data));
        desc_list_.push_back(std::move(desc));
    }

    template <typename Callback>
    void run(Callback cb) {
        // C++11/C++14 template execution pipeline logic
        // Processes payload fragmentation and triggers callback per fragment
    }

private:
    uint16_t segment_size_;
    std::list<binary_t> data_list_;
    std::list<Descriptor> desc_list_;
};

} // namespace net
} // namespace hotplace

```

### 2) `dtls_record_publisher.cpp` (DTLS Handshake Split Implementation)

핸드셰이크 헤더를 제어하고 세그먼트에 맞게 단편화 record를 생성 및 결합하는 실제 분할 동작부

```cpp
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>

namespace hotplace {
namespace net {

dtls_record_publisher::dtls_record_publisher()
    : _session(nullptr), _fragment_size(1024), _segment_size(1200), _flags(0) {}

void dtls_record_publisher::set_fragment_size(uint16 size) {
    const uint16 minsize = 1 << 7;
    const uint16 maxsize = 1 << 10;
    adjust_range(size, minsize, maxsize);
    _fragment_size = size;
}

// Published DTLS Handshake record fragmentation logic
return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::list<binary_t>& container) {
    // Process TLS/DTLS record payload and split into fragments matching MTU limits
    // Utilizes lambda callbacks for segment generation and handshake header adjustments
    return errorcode_t::success;
}

}  // namespace net
}  // namespace hotplace

```

### 3) 주요 API 및 컴포넌트 구성

| 구분 | 이름 | 설명 |
| --- | --- | --- |
| **클래스** | `dtls_record_publisher` | DTLS 핸드셰이크/record 패킷을 세그먼트 크기에 맞춰 생성 및 lambda 콜백 발행 |
| **템플릿 클래스** | `splitter<Descriptor>` | 주어진 버퍼 데이터를 metadata(`spl_desc`)와 함께 단편화 분할 처리 |
| **구조체** | `spl_desc` | DTLS 핸드셰이크 타깃 정보(`hstype`, `hsseq`)를 보관하는 metadata 디스크립터 |
| **핵심 메서드** | `publish()` | DTLS record를 처리 및 단편화하여 이진 바이트 스트림 리스트로 내보냄 |

---

## 3. C++11 Runtime / C++14 Compile-time 실습 code (DTLS Splitter Integration Usage)

```cpp
#include <iostream>
#include <vector>
#include <list>
#include <functional>
#include <cstdint>
#include <cstring>

namespace hotplace {

// Stream Metadata Descriptor
struct spl_desc {
    uint16_t hstype;
    uint16_t hsseq;
};

// Generic C++11/C++14 Stream Splitter
template <typename Descriptor>
class splitter {
public:
    splitter() : segment_size_(1200) {}

    void set_segment_size(uint16_t size) { segment_size_ = size; }

    void add(std::vector<uint8_t>&& data, Descriptor&& desc) {
        stream_data_ = std::move(data);
        desc_ = std::move(desc);
    }

    // Process fragmentation with C++11 Lambda execution
    void run(std::function<void(uint32_t flags, const uint8_t* stream, size_t size,
                                size_t fragoffset, size_t fragsize, const Descriptor& desc)> callback) {
        size_t total_size = stream_data_.size();
        size_t offset = 0;

        while (offset < total_size) {
            size_t chunk = (total_size - offset > segment_size_) ? segment_size_ : (total_size - offset);
            uint32_t flags = (offset == 0) ? 0x01 : 0x00; // 0x01: New Segment Flag

            callback(flags, stream_data_.data(), total_size, offset, chunk, desc_);
            offset += chunk;
        }
    }

private:
    uint16_t segment_size_;
    std::vector<uint8_t> stream_data_;
    Descriptor desc_;
};

} // namespace hotplace

int main() {
    // DTLS Handshake data simulation (3000 bytes raw payload)
    std::vector<uint8_t> raw_handshake(3000, 0xAB);

    hotplace::spl_desc desc;
    desc.hstype = 2; // ServerHello
    desc.hsseq = 1;  // Sequence Number 1

    hotplace::splitter<hotplace::spl_desc> spl;
    spl.set_segment_size(1000); // Set Max Fragment Size to 1000 Bytes
    spl.add(std::move(raw_handshake), std::move(desc));

    std::cout << "[DTLS Stream Fragmentation Engine Test]" << std::endl;

    // Run fragmentation callback execution
    spl.run([](uint32_t flags, const uint8_t* stream, size_t size,
               size_t fragoffset, size_t fragsize, const hotplace::spl_desc& d) {
        std::cout << " - Fragment Sequence [" << d.hsseq << "] | Offset: " << fragoffset
                  << " | Fragment Size: " << fragsize
                  << " | Total Size: " << size
                  << " | Flag: " << flags << std::endl;
    });

    return 0;
}

```

---

## 4. 프로그래밍 TODO list 및 우선순위 관리 (TODO List)

### 📌 TODO List Tracker

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-DRP-01** | `HIGH` | **DTLS 1.3 record publisher fragmentation 및 arrange 연동**<br>- `testcase_construct_dtls13.cpp` 내 `construct_record_fragmented()` 및 `get_dtls_record_arrange()` 적용을 통한 record fragmentation 및 reassemble 테스트 추가 | `To Do` | `testcase_construct_dtls13.cpp` |
| **TODO-DRP-02** | `HIGH` | **다중 구분자(Multi-delimiter) 및 가변 길이 DTLS segment 분할 로직 보완**<br>- 여러 payload pattern을 동시에 처리하는 network buffer 분할 최적화 구현 | `In Progress` | `dtls_record_publisher.cpp` |
| **TODO-DRP-03** | `MEDIUM` | **공백 제거(Trim) 및 DTLS Handshake Header trimming 옵션 추가**<br>- token 분할 및 fragment 생성 시 header/전후 padding을 제거하는 flag parameter 연동 | `To Do` | 기능 확장 |
| **TODO-DRP-04** | `MEDIUM` | **DTLS 1.3 multi_handshakes flag 검증 케이스 추가**<br>- 단일 DTLS 1.3 record 내 multiple handshake message 포함 시 `dtls_record_publisher_multi_handshakes` flag 동작 및 arrange 정상 처리 여부 검증 | `To Do` | `testcase_construct_dtls13.cpp` |
| **TODO-DRP-05** | `LOW` | **성능 benchmark 테스트 케이스 작성**<br>- 대용량 DTLS stream fragmentation 분할 시 benchmark 측정 및 profiling 수행 | `To Do` | benchmark 검증 |
