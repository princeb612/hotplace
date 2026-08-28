# DTLS Record Fragmentation & Stream Splitter - published by Gemini

## 1. Overview & Design Pattern

The **DTLS Record Publisher & Stream Splitter Engine** performs fragmentation and reassembly (segmentation & fragmentation) on handshake messages and data records in a DTLS (Datagram Transport Layer Security) protocol-based network communication environment. It adheres to compile-time and runtime constraints while complying with maximum transmission unit (PMTU / Segment Size) and fragment size limitations.

### Key Features

* **DTLS Fragmentation Support**: Manages DTLS message sequences (`hsseq`) and trims handshake headers to segment packets into fragmented handshake packets (`dtls_handshake_fragmented`) under MTU size limits.
* **C++11 Runtime & C++14 Compile-Time Support**:
  * **Runtime**: C++11 specification-based execution managing memory and resources using lambda functions (`std::function`), smart pointers, and STL containers.
  * **Compile-Time**: Template-based pipeline extension support leveraging relaxed C++14 `constexpr` constraints and standard template metaprogramming utilities (`std::make_index_sequence`, `std::index_sequence`).
* **RAII Pattern and Template Handling**: Prevents resource leaks by applying memory cleanup, object lifecycle management, and reference counting (`addref`/`release`).

---

## 2. API Reference & Core Architecture Analysis

### 1) `splitter.hpp` & `dtls_record_publisher.hpp` (Core Engine & Declarations)

Declarations for the `splitter<T>` template class managing stream and handshake fragmentation, and the DTLS record publisher:

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

The actual splitting logic component that controls handshake headers and creates/combines fragmented records matching segment sizes:

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

### 3) Core Component Overview

| Category | Component Name | Description |
| --- | --- | --- |
| **Class** | `dtls_record_publisher` | Generates DTLS handshake/record packets according to segment sizes and emits lambda callbacks |
| **Template Class** | `splitter<Descriptor>` | Splits provided buffer data together with metadata (`spl_desc`) |
| **Struct** | `spl_desc` | Metadata descriptor holding DTLS handshake target information (`hstype`, `hsseq`) |
| **Core Method** | `publish()` | Processes and fragmentates DTLS records to export them into a binary byte stream list |

---

## 3. TODO List Tracker

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-DRP-01** | `HIGH` | **DTLS 1.3 record publisher fragmentation & arrange integration**<br><br>- Add record fragmentation and reassembly test cases by applying `construct_record_fragmented()` and `get_dtls_record_arrange()` in `testcase_construct_dtls13.cpp` | `To Do` | `testcase_construct_dtls13.cpp` |
| **TODO-DRP-02** | `HIGH` | **Enhance multi-delimiter & variable-length DTLS segment splitting logic**<br><br>- Implement network buffer splitting optimizations to handle multiple payload patterns simultaneously | `In Progress` | `dtls_record_publisher.cpp` |
| **TODO-DRP-03** | `MEDIUM` | **Add whitespace trimming and DTLS Handshake Header trimming options**<br><br>- Integrate flag parameters to strip headers or pre/post padding during token splitting and fragment generation | `To Do` | Feature Extension |
| **TODO-DRP-04** | `MEDIUM` | **Add DTLS 1.3 multi_handshakes flag verification cases**<br><br>- Verify `dtls_record_publisher_multi_handshakes` flag operations and proper arrange processing when multiple handshake messages are contained within a single DTLS 1.3 record | `To Do` | `testcase_construct_dtls13.cpp` |
| **TODO-DRP-05** | `LOW` | **Write performance benchmark test cases**<br><br>- Perform benchmark measurement and profiling during large-scale DTLS stream fragmentation splitting | `To Do` | Benchmark Verification |
