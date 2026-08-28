## CBOR (Concise Binary Object Representation) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 library module that creates, encodes, decodes, and parses standard binary data formats according to RFC 8949 (CBOR) specifications.
* **Key Features**:
  * **Object Model-based Design**: Implements primitive types (`cbor_data`), byte/text strings (`cbor_bstrings`, `cbor_tstrings`), composite types (`cbor_array`, `cbor_map`, `cbor_pair`), and tag/simple values (`cbor_simple`) using an inheritance structure derived from `cbor_object`.
  * **Encoding & Decoding**: Stream binary serialization via `cbor_encode` and buffer stream decoding/parsing via `cbor_reader`.
  * **Debugging and Delivery Architecture**: Supports AST traversal/dumping via `cbor_visitor` and the `cbor_publisher` pattern.
* **C++11 Features**:
  * Memory control based on a reference counting (`addref`/`release`) style rather than smart pointers (`std::shared_ptr`, `std::unique_ptr`).
  * C++11 data movement and lambda utilization centered around `std::vector<uint8_t>`, `std::string`, and standard STL containers.

---

### 2. Main Class and API Structure

**CBOR Object and Factory Structure (`cbor_object`)**

```cpp
namespace hotplace {

// Top-level Abstract Data Object
class cbor_object {
   public:
    virtual cbor_type_t type() const = 0;
    virtual int addref();
    virtual int release();
};

// CBOR Encoder and Decoder
class cbor_encode {
   public:
    cbor_encode& encode(const cbor_object* object, binary_t& stream);
};

class cbor_reader {
   public:
    int parse(const uint8_t* buffer, size_t size, cbor_object** out);
};

}  // namespace hotplace

```

---

### 3. Core Operating Mechanism

* **Class Breakdown by Primary Types**:
  * `cbor_data`: Represents integer (Unsigned/Negative Integer) and floating-point data.
  * `cbor_bstrings` / `cbor_tstrings`: Manages binary byte strings and UTF-8 text strings.
  * `cbor_array` / `cbor_map`: Container objects holding elements sequentially or in Key-Value pairs.
  * `cbor_simple`: Handles CBOR Simple Values (true/false/null/undefined) and Tagged types.
* **Encoding & Decoding Mechanism**:
  * `cbor_encode`: Assembles the CBOR Major Type Header (3-bit Major Type + 5-bit Additional Info) via bitwise operations and sequentially writes data payloads into a `binary_t` stream.
  * `cbor_reader`: Interprets the first byte (Major Type) of the binary stream to reconstruct the corresponding object type (`cbor_object`-derived class) and build a tree structure.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-CBOR-01** | Refine boundary validation for indefinite-length binary/text stream parsing in `cbor_reader::parse`<br> | High | Open |
| **TODO-CBOR-02** | Review refactoring manual reference counting (`addref`/`release`) in the `cbor_object` hierarchy to a standard C++11 `std::shared_ptr`-based model | Medium | Open |
| **TODO-CBOR-03** | Apply memory pooling and minimize temporary buffer reallocations to optimize `cbor_encode` performance | Low | Open |
