## QPACK (HTTP/3 Header Compression) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: An HTTP/3 standard (RFC 9204)-based header compression/decompression, separate Encoder/Decoder stream control, and static/dynamic table operations module.
* **Key Features**:
  * **Static Table Parsing and Lookup**: Performs index mapping and key-value lookup operations for the 99 static header entries defined in RFC 9204 (`qpack_static_table.cpp`, `qpack_static_table.hpp`).
  * **Dynamic Table and Absolute/Relative Indexing**: Performs conversion operations between Absolute Index and Relative Index over Encoder/Decoder streams, alongside capacity-based eviction handling (`qpack_dynamic_table.cpp`, `qpack_dynamic_table.hpp`).
  * **QPACK Encoder Operations**: Handles field line encoding, prefix integer / literal representation operations, and generates encoder stream instructions (`qpack_encoder.cpp`, `qpack_encoder.hpp`).
  * **QPACK SDK Facade and Interface**: Provides an integrated QPACK processing facade and external integration interfaces (`qpack_sdk.cpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **Static Table Lookup Operations (`qpack_static_table.cpp`, `qpack_static_table.hpp`)**:
  * Executes fast $O(1)$ index access and lookup operations for the 99 static table entries specified in RFC 9204.
* **Dynamic Table and Index Conversion Operations (`qpack_dynamic_table.cpp`, `qpack_dynamic_table.hpp`)**:
  * Controls conversions between Absolute Index <-> Relative Index / Post-Base Index to prevent HTTP/3 head-of-line blocking.
  * Manages FIFO-based entry eviction and entry count tracking when exceeding dynamic table memory limits.
* **QPACK Encoder and Instruction Generation (`qpack_encoder.cpp`, `qpack_encoder.hpp`)**:
  * Performs field line encoding by computing Required Insert Count and Base Index.
  * Supports literal field line encoding operations with name reference / literal name representation.
* **QPACK SDK Integration Interface (`qpack_sdk.cpp`)**:
  * Provides a C++11 facade interface serving as a bridge between the HTTP/3 protocol layer and the QPACK Encoder/Decoder.

---

### 3. Core Operating Mechanism

* **Index Translation Mechanism (`qpack_dynamic_table.cpp`)**:
  * When accessing dynamic table entries, translates Absolute Indices into Relative Indices or Post-Base Indices relative to a reference base point to perform header block encoding.
* **Header Field Encoding & Stream Handling (`qpack_encoder.cpp`, `qpack_sdk.cpp`)**:
  * Converts incoming HTTP/3 header lists depending on static/dynamic table mapping status, then assembles and transmits encoder stream instructions.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-QPACK-01** | Strengthen Base Index overflow and out-of-bounds (OOB) exception handling during Relative Index conversion in `qpack_dynamic_table.cpp`<br> | High | Open |
| **TODO-QPACK-02** | Verify Required Insert Count calculation logic validity and unacknowledged entry limits in `qpack_encoder.cpp`<br> | High | Open |
| **TODO-QPACK-03** | Verify QPACK dynamic table reference count cleanup upon HTTP/3 stream cancellation in `qpack_sdk.cpp`<br> | Medium | Open |
| **TODO-QPACK-04** | Supplement safe lookup exception handling when accessing static table indices out of range in `qpack_static_table.cpp`<br> | Medium | Open |
| **TODO-QPACK-05** | Check Huffman encoding decision logic and bit parsing boundary checks in `qpack_encoder.cpp`<br> | Low | Open |
