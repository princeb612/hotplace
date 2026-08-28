제공해주신 `basic_stream` 및 `bufferio` 문서 [source: 6]를 영문으로 변환하였습니다.

---

## `basic_stream` and `bufferio` - published by Gemini

### 1. Overview and Design Pattern

The `basic_stream` module is a dynamic stream buffer class created by combining `bufferio` (the internal data chunk management layer) and `traits_printf` (the type handling layer).
It simultaneously offers the I/O usability of the C++ standard `std::stringstream` and the memory/speed efficiency of C-style buffer processing.

#### Key Features

1. **Chunk-Based Dynamic Memory Management (`bufferio`)**:
  * Allocates data via a chunk list (`bufferin_queue_t`) to minimize frequent `realloc` overhead.
  * Automatically flattens into a single contiguous block upon read requests (`c_str()`, `data()`).
2. **Type-Trait-Based Printf Pipeline (`printf_traits`)**:
  * Automatically abstracts integer, enum, and floating-point types using metaprogramming to map format strings (`%d`, `%u`, `%f`, etc.).
  * Simplifies complex SFINAE conditions into `printf_traits` to improve maintainability.
3. **Strong Exception Guarantee**:
  * Applies the Copy-and-Swap idiom to the copy assignment operator (`operator=`).
4. **Stream Custom Extensibility (`encoder_stream_traits`)**:
  * Integrates directly with external encoder/decoder algorithms via `custom::encoder_stream_traits<basic_stream>` specialization.

---

### 2. Core Classes and API Reference

#### Key Components

* **`bufferio`**: Handles low-level dynamic buffer operations such as memory chunk allocation (`extend`), merging, C-string conversion, slicing (`cut`), and insertion (`insert`).
* **`printf_traits`**: Metaprogramming traits that automatically convert C++ types into C-style `printf` format specifiers and casting types.
* **`basic_stream`**: Implements the `stream_t` interface, providing operator overloading (`<<`, `+=`, `==`) and a C++ style stream interface.

#### Major Methods Analysis

| Class / Method | Description and Functionality |
| --- | --- |
| **`basic_stream::operator<<`** | Sequentially serializes primitive types, `std::string`, `binary_t`, `bignumber`, `variant`, etc. into the stream. |
| **`basic_stream::printf` / `println**` | Receives variadic arguments and calls internal `bufferio::vprintf` to append data. |
| **`basic_stream::vaprintf`** | Combines custom `valist` objects with format templates (`{1}`, `{2:04x}`, etc.) for formatted output. |
| **`basic_stream::cut(pos, len)`** | Adjusts the buffer chunk to delete `len` bytes starting from `pos`. |
| **`basic_stream::insert(pos, ptr, len)`** | Splits and inserts a new memory chunk at the specified position. |
| **`basic_stream::resize(s)`** | Changes buffer size; performs `cut` when shrinking, and `fill(0)` when expanding. |

---

### 3. Internal Architecture

#### 3.1. Type-Trait Mapping Pipeline (`printf_traits`)

When calling `operator<<` with variable types, `printf_traits` derives C-style `printf` format specifiers through the following pipeline:

```
[Input Type T]
      │
      ▼
std::decay<T>::type ──► Enum Check (integral_type)
      │
      ▼
Size (sizeof) & Signedness Check
      │
      ▼
Select cast_type (int / unsigned int / long long, etc.)
      │
      ▼
Extract format_specifier_traits<BT, final_type>::spec ("%d", "%u", "%lld", etc.)

```

* **Performance Optimization**: Single `char` and `const char*` perform direct memory copying via `bufferio::write` to avoid `printf` format parsing overhead.

#### 3.2. Buffer Flattening

`bufferio` uses an internal `std::list<bufferio_t*>` structure to allocate memory in block units during write operations.

```
[Write Operations]
Queue: [Block 1 (1024b)] -> [Block 2 (1024b)] -> [Block 3 (256b)]

[c_str() / data() Call]
1. Allocate a single contiguous block (Total Size)
2. Copy all block data from Queue & append NUL padding
3. Release original Queue blocks and replace with single block
Result: [Single Contiguous Block (2304b)]

```

---

### 4. C++11 Usage Example

```cpp
#include <iostream>
#include <hotplace/sdk/base/stream/basic_stream.hpp>

void run_basic_stream_sample() {
    using namespace hotplace;

    // -------------------------------------------------------------
    // Demo 1: Operator Insertion & Basic Data Append
    // -------------------------------------------------------------
    basic_stream bs;
    bs << "Header: " << 100 << ", Flag: " << true << ", Value: " << 3.14159;
    bs.println(" [END]");

    std::cout << "[Demo 1 Output]\n" << bs.c_str();

    // -------------------------------------------------------------
    // Demo 2: String Formatting with vaprintf (valist)
    // -------------------------------------------------------------
    basic_stream bs_fmt;
    valist va;
    va << 256 << "hello world" << 3.141592;

    // Format syntax: {n}, {n:04x}, {n:-15s}, {n:lf}
    bs_fmt.vaprintf("HEX: {1:04x}, STR: {2:-15s}, FLOAT: {3:lg}", va);

    std::cout << "\n[Demo 2 Output]\n" << bs_fmt.c_str() << "\n";

    // -------------------------------------------------------------
    // Demo 3: Buffer Slicing and Dynamic Cut/Insert
    // -------------------------------------------------------------
    basic_stream bs_buf("0123456789");
    bs_buf.cut(2, 4); // Remove "2345" -> "016789"
    bs_buf.insert(2, "ABCD", 4); // Insert "ABCD" at pos 2 -> "01ABCD6789"

    std::cout << "\n[Demo 3 Output]\n" << bs_buf.c_str() << "\n";
}

int main() {
    run_basic_stream_sample();
    return 0;
}

```

---

### 5. TODO List Tracker

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-BS-01** | `HIGH` | **Optimize lock scope in `bufferio::insert**`<br><br>- Add safeguards and narrow lock contention scope during chunk splitting and memory allocation exceptions | `Postponed` | `bufferio.cpp`<br> |
| ~~**TODO-BS-02**~~ | `HIGH` | **Cross-platform verification of 128-bit integer format specifiers**<br><br>- Review `%I128i` / `%I128u` format string compatibility under `__SIZEOF_INT128__` supported environments | `No change required` | Existing test case `testcase_stream.cpp`<br> |
| ~~**TODO-BS-03**~~ | `MEDIUM` | **Improve large padding speed in `basic_stream::fill**`<br><br>- Optimize bypass of `memset` allocation loop based on chunk size (256 bytes) | `No change required` | `basic_stream.cpp`<br> |
| **TODO-BS-04** | `MEDIUM` | **Design `std::string_view` overloading interface (for C++17)**<br><br>- Maintain C++11 standard while pre-defining a view-type compatible wrapper layer | `To Do` | `operator<<` extension |
| **TODO-BS-05** | `LOW` | **Redefine platform boundaries to reduce Wide String overhead**<br><br>- Linux: Focus on `char*` (UTF-8) processing to minimize 4-byte `wchar_t` allocations<br><br>- Windows: Isolate `wchar_t` conversions to Win32 API call sites (`ansi2wide`/`wide2ansi`) | `To Do` | `unicode/` & `windows/`<br> |

* **TODO-BS-05: Redefining Cross-Platform Abstraction Direction**
  * **Linux / POSIX**:
    * Use `char*` / `std::string` (UTF-8) as the primary and only internal stream buffer type.
    * Deprecate or minimize `wchar_t` related functions (`bufferio_wcs`, `printf_wcs`) into simple UTF-8 output/conversion wrappers in POSIX environments.
  * **Windows**:
    * Enforce conditional compilation (`_WIN32`) only at points requiring **UTF-16 LE (`wchar_t`, 2 bytes)** conversion (`windows/ansi2wide.cpp`, `wide2ansi.cpp`) for Win32 API interoperability.
    * **Historical Context: UCS-2 and UTF-16**:
      * *Windows NT Era*: Adopted **UCS-2 (Fixed 2-byte)** encoding as the default system string (`wchar_t`) model for OS APIs, commonly referred to as "UNICODE".
      * *UTF-16 Expansion*: As Unicode expanded, **UTF-16** (Surrogate Pairs, 2 to 4 bytes variable) was introduced to support code points outside the Basic Multilingual Plane.
      * *Current Windows API*: Operates on **UTF-16 Little Endian** internally, though legacy naming (`UNICODE`, `WCHAR`, `LPCWSTR`) persists across headers and macros.
    * **Key Differences from POSIX (Linux) `wchar_t**`:
      * *Windows*: `wchar_t` is defined as 2 bytes (UTF-16 LE) and used as the native encoding for Win32 API functions (`CreateWindowW`, `CreateFileW`, etc.).
      * *Linux/POSIX*: `wchar_t` is defined as 4 bytes (UTF-32/UCS-4), while standard system calls and filesystems default to UTF-8 (`char*`).
