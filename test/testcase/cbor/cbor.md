## CBOR (Concise Binary Object Representation) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 library module that encodes, decodes, and parses binary-based data structures in compliance with the RFC 8949 (formerly RFC 7049) standard specification.
* **Key Features**:
  * **Standard Test Vector Verification**: Configures official RFC verification testers based on `testcase_rfc7049.cpp`, `testvector_cbor.cpp`, and `testvector_cbor.yml`.
  * **Object-Model-Based Design**: Inherits from `cbor_object` to represent integers/data (`cbor_data`), text/byte strings (`cbor_tstrings`, `cbor_bstrings`), arrays/maps (`cbor_array`, `cbor_map`), and tags/simple values (`cbor_simple`).
  * **Serialization and Binary Decoding**: Generates stream binaries via `cbor_encode` and reconstructs object trees through `cbor_reader` parsing.
  * **Visitor Pattern & Transmission Structure**: Supports AST traversal/dumping via `cbor_visitor` and the `cbor_publisher` pattern.
* **C++11 Features**:
  * Resource control and memory lifecycle management using a reference counting (`addref`/`release`) style approach.
  * Data transfer operations centered around `std::vector<uint8_t>`, `std::string`, and C++11 STL mechanisms.

---

### 2. Core Classes and API Structure

**CBOR Core Objects and Verification Tester**

```cpp
namespace hotplace {

// Top-level abstract data object
class cbor_object {
   public:
    virtual cbor_type_t type() const = 0;
    virtual int addref();
    virtual int release();
};

// CBOR encoder and decoder
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

* **Class Structure by Key Type**:
  * `cbor_data`: Represents unsigned/negative integer and floating-point numerical data.
  * `cbor_bstrings` / `cbor_tstrings`: Controls byte strings and UTF-8 text string binaries.
  * `cbor_array` / `cbor_map`: Manages sequential element lists and key-value mapping objects.
  * `cbor_simple`: Handles simple values (true/false/null/undefined) and tagged data.
* **RFC 8949 / RFC 7049 Standard Verification Mechanism**:
  * Parses standard RFC test vectors specified in `testvector_cbor.yml` and `testcase_rfc7049.cpp` to automatically verify that binary encoding and decoding results strictly align with the specification.
* **Encoding & Decoding Operations**:
  * `cbor_encode`: Combines the Major Type Header (3-bit Major Type + 5-bit Additional Information) and sequentially writes the data payload into a `binary_t` stream.
  * `cbor_reader`: Interprets the header region of the binary stream to dynamically instantiate corresponding `cbor_object` derived objects and reconstruct the tree.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-CBOR-01** | Refine boundary validation when parsing indefinite-length binary/text streams in `cbor_reader::parse`<br> | High | Open |
| **TODO-CBOR-02** | Evaluate refactoring manual reference counting (`addref`/`release`) in `cbor_object` classes to a standard C++11 `std::shared_ptr`-based model | Medium | Open |
| **TODO-CBOR-03** | Minimize temporary buffer reallocations and apply memory pooling to optimize `cbor_encode` performance | Low | Open |
| **TODO-CBOR-04** | Extend `testvector_cbor.yml` with recent RFC 8949 edge cases and improve debug log outputs | Low | Open |
