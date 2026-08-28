# `payload` and `payload_member` - published by Gemini

---

## 1. Overview & Design Pattern

The `payload` module is a C++11 builder pattern-based data parsing framework designed for flexible serialization (Write) and deserialization (Read/Parse) of network protocol packets (TLS, DTLS, QUIC, etc.).

### Key Features

1. **Flexible Field Metadata Configuration (`payload_member`)**:
  * Automatic abstraction for integer types (int8 to uint128), endianness (Big/Little Endian), variable-length binary, strings, Bignumbers, and encoded types.
2. **Dynamic Field Reference Operations (`set_reference_value`)**:
  * Automatic binding for structures where a specific field's length depends on the value of a preceding field (e.g., Length Field -> Payload).
3. **Conditional Fields and Group Control (`set_group`, `set_condition`)**:
  * Supports dynamic parsing by enabling/disabling subgroups (`set_group`) or triggering hook callbacks (`set_condition`) based on specific flag or header values.
4. **Heuristic Reading (Speculative Variable Parsing)**:
  * Performs slicing parsing by inferring remaining area relative to total buffer size when items of unknown length (`list_size_unknown`) exist.

---

## 2. API Reference & Core Class Structure

### Core Class Roles

* **`payload_member`**: Represents a single data item inside a packet. Handles endianness conversion, memory allocation, and reference operations.
* **`payload_encoded`**: Interface specification for variable-length representation schemes (e.g., QUIC variable-length integer, etc.).
* **`payload`**: Container that registers multiple `payload_member` instances via chaining to manage binary reading/writing and conditional parsing.

### Core Methods Analysis

| Class / Method | Role & Description |
| --- | --- |
| **`payload::operator<<`** | Intuitively chain-adds fields based on `unique_ptr` or `t_pointer_proxy`. |
| **`set_reference_value(name, ref, mult)`** | Dynamically sets the size of the `name` field to the value of `ref` field $\times$ `mult` size. |
| **`set_condition(name, hook)`** | Registers a callback function to be executed after the `name` field is parsed (enables dynamic group condition modification). |
| **`read(ptr, size, pos)`** | Reads and parses data from a binary stream in the order of registered members. |
| **`write(bin, groups)`** | Serializes and outputs active group data from registered members to a binary stream. |
| **`t_value_of<T>(name)`** | Safely extracts the value of a parsed member cast to type $T$. |

---

## 3. C++11 Example Usage

Complies with `C++11` standard:

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

## 4. TODO List Tracker

ID-based TODO tracker for ensuring module stability and performance optimization:

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-PL-01** | `HIGH` | **Strengthen `list_size_unknown` exception handling in `read()**`<br><br>- Verify exception return handling when 2+ unknown-size members exist and supplement variable-length bound checks | `In Progress` | `read()` 2nd pass logic |
| **TODO-PL-02** | `HIGH` | **Verify memory allocation/deallocation leak in `payload_member**`<br><br>- Standardize ownership transfer structure to `std::unique_ptr` instead of RAW pointer passing | `To Do` | Clean up `operator<<`<br> |
| **TODO-PL-03** | `MEDIUM` | **Optimize endian conversion utilities inside `doread**`<br><br>- Strengthen byte offset boundary checks when mapping 24-bit/48-bit numbers besides `ntoh16`/`ntoh32`/`ntoh64`<br> | `To Do` | `doread()` value conversion |
| **TODO-PL-04** | `MEDIUM` | **Review execution order guarantees for multi-hooks in `set_condition**`<br><br>- Ensure reliability of callback execution order when registering identical keys in `std::multimap`<br> | `In Progress` | `_cond_map` structure |
| **TODO-PL-05** | `LOW` | **Improve group filtering performance during `payload::write**`<br><br>- Consider switching to hash/flag-based group identifiers to reduce `std::set<std::string>` lookup overhead | `To Do` | Improve serialization performance |
