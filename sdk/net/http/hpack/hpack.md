## HPACK (HTTP/2 Header Compression) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: An HTTP/2 standard (RFC 7541)-based header compression/decompression and static/dynamic table management operations module.
* **Key Features**:
  * **Static Table Parsing and Lookup**: Index-based lookup for predefined HTTP header names and values (`hpack_static_table.cpp`, `hpack_static_table.hpp`).
  * **Dynamic Table Lifecycle Control**: Maintains runtime received header encoding/decoding states, with FIFO-based memory size limits and eviction handling (`hpack_dynamic_table.cpp`, `hpack_dynamic_table.hpp`).
  * **HPACK Encoder Operations**: Encodes primitive types (Integer, Literal), performs Huffman coding, and generates Header Blocks (`hpack_encoder.cpp`, `hpack_encoder.hpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **Static Table Lookup Operations (`hpack_static_table.cpp`, `hpack_static_table.hpp`)**:
  * Provides $O(1)$ index mapping and key-value lookup functionality for the 61 static header entries defined in RFC 7541.
* **Dynamic Table FIFO Management and Eviction (`hpack_dynamic_table.cpp`, `hpack_dynamic_table.hpp`)**:
  * Implements an eviction mechanism that automatically purges older entries when the dynamic table capacity exceeds `SETTINGS_HEADER_TABLE_SIZE`.
  * Applies accurate byte weight calculations including overhead (32 bytes) when determining entry size.
* **HPACK Header Encoding and Representation (`hpack_encoder.cpp`, `hpack_encoder.hpp`)**:
  * Supports Indexed Header Field and Literal Header Field representations (Incremental Indexing / Without Indexing / Never Indexed).
  * Performs variable-length integer encoding and prefix bit masking operations.

---

### 3. Core Operating Mechanism

* **Dynamic Table Entry Eviction (`hpack_dynamic_table.cpp`)**:
  * When adding a new header entry, if current table usage exceeds maximum capacity, eviction operations are performed starting from the tail area in FIFO order.
* **HPACK Integer & Literal Representation (`hpack_encoder.cpp`)**:
  * Encodes integer values according to prefix bits and selects appropriate literal representation encodings based on static/dynamic table index mapping status.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-HPACK-01** | Supplement capacity reduction overflow and eviction exception handling during dynamic table size updates in `hpack_dynamic_table.cpp`<br> | High | Open |
| **TODO-HPACK-02** | Verify encoder implementation validity and boundary bit/byte alignment for Huffman encoding in `hpack_encoder.cpp`<br> | High | Open |
| **TODO-HPACK-03** | Verify out-of-bounds (OOB) handling when accessing static table indices out of range in `hpack_static_table.cpp`<br> | Medium | Open |
| **TODO-HPACK-04** | Verify accuracy of the 32-byte overhead addition criteria when inserting dynamic table entries | Medium | Open |
| **TODO-HPACK-05** | Check buffer overflow exception handling for large integer inputs during N-bit prefix integer encoding in `hpack_encoder.cpp`<br> | Low | Open |
