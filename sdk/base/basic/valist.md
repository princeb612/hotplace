# Dynamic `va_list` Generation (`valist`) - published by Gemini

## 1. Overview & Key Features

The `valist` module is a C++11 wrapper class designed to dynamically construct a variable argument list (`va_list`) at runtime and pass it to `vprintf`-family functions.

* **Platform-Compatible Memory Layout Generation**: Dynamically rearranges argument memory considering ABI differences between Windows and Linux (x86, x86_64).
* **Default Argument Promotion Handling**: Complies with C variadic calling conventions by promoting `float` to `double` and `char`/`short` to integer types.
* **Synchronization & Safety**: Utilizes `critical_section_guard` to ensure thread safety in multithreaded environments.
* **C++11 Feature Utilization**: Supports move insertion via Move Semantics (`std::move`) and leverages the `auto` keyword.

---

## 2. Key Implementation Areas & Technical Elements

* **Dynamic ABI Layout Synthesis**: Synthesizes an artificial stack structure in Linux x86_64 environments by forcibly setting `va_list` register offsets to maximum values (`gp_offset = 48`, `fp_offset = 304`), bypassing register allocation and reading all arguments directly from the `overflow_arg_area` memory region.
* **Type Promotion & Padding Compliance**: Expands small integer types and single-precision floating-point types according to C calling conventions (Default Argument Promotion), guaranteeing memory alignment and padding aligned with architecture chunk sizes (`VLIST_CHUNK_SIZE`: 4 bytes for x86, 8 bytes for x64).
* **Heterogeneous Type Encapsulation**: Abstractly encapsulates arguments of various types into `variant_t` objects, dynamically collecting and managing them inside an internal vector (`_args`).
* **Thread-Safe State Synchronization**: Controls the `_modified` flag during argument addition and updates, embedding a critical section (`critical_section`) to guarantee synchronization during multithreaded argument construction.

---

## 3. Major Data Structures, Classes & API Reference

### Core Data Structures

```cpp
namespace hotplace {

// Linux x86_64 GCC va_list internal structure mapping
typedef struct _valist_gcc_x64_t {
    unsigned int gp_offset;
    unsigned int fp_offset;
    void* overflow_arg_area;
    void* reg_save_area;
} valist_gcc_x64_t[1];

typedef struct _valist_t {
    union {
        va_list ap;
        void* va_ptr;
#if defined __linux__ && __WORDSIZE == 64
        valist_gcc_x64_t gcc_va_list64;
#endif
    };
} valist_t;

```

### Main Classes & Methods

| Class / Method | Description & Functionality |
| --- | --- |
| **`valist`** | Primary class responsible for dynamically generating and managing a `va_list`. |
| `operator<<(value)` | Stream operator that converts arguments of various types into `variant_t` and collects them. |
| `get()` | Returns a `va_list&` reference dynamically constructed according to the platform. |
| `build()` | (protected) Aligns memory layouts for the target platform ABI and constructs internal `va_list` structures. |
| `clear()` / `size()` | Resets the collected argument buffer or returns the argument count. |

---

## 4. Operational Principles

1. **Dynamic Argument Collection**: Accumulates primitive types (`bool`, `int`, `double`, `const char*`, etc.) and `variant_t` objects passed via `operator<<` into `std::vector<variant_t>` and sets `_modified = true`.
2. **Platform Memory Layout Calculation (`build`)**: Performs memory building when argument modification is detected upon calling `get()`.
* **Linux x86_64**: Maxes out offset indices to disable the register area and binds a contiguous memory block to `overflow_arg_area`.
* **Windows / x86**: Allocates a contiguous buffer (`arg_list`) and executes type-specific 4/8-byte boundary padding copies following `va_assign` macros and CRT rules.
3. **`va_list` Pointer Binding & Settlement**: Maps the starting address of the copied byte buffer to the `ap` pointer of the internal wrapper structure (`valist_t`), returning it in a state ready to be consumed immediately by standard `vsnprintf`-family APIs.

---

## 5. Usage Example (C++11 Standard)

```cpp
#include <iostream>
#include <vector>
#include <hotplace/sdk/base/basic/valist.hpp>

void custom_vprintf(const char* format, hotplace::valist& vl) {
    // Retrieve dynamically created va_list and call vprintf
    vprintf(format, vl.get());
}

int main() {
    using namespace hotplace;

    valist args;
    
    // Dynamic argument collection via C++11 Fluent/Streaming interface
    args << 42 
         << 3.14159 
         << "Dynamic va_list Test";

    const char* fmt = "Integer: %d, Double: %.2f, String: %s\n";

    // Pass dynamic va_list and print
    custom_vprintf(fmt, args);

    return 0;
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| ~~**TODO-VA-01**~~ | `MEDIUM` | **Verify x64 ABI Boundary & Alignment**<br><br>- `testvector_valist.yml` - Verified PASS under development AppVerifier environment | `Fixed` | Test cases implemented |
| **TODO-VA-02** | `HIGH` | **Prevent Memory Fragmentation**<br><br>- Replace `malloc`/`free` calls inside `build()` with dedicated memory pool or `std::vector<uint8_t>` | `Postponed` | Not started |
| **TODO-VA-03** | `MEDIUM` | **Extend ARM64 (AArch64) Support**<br><br>- Expand `valist_t` register packing structure to support ARM64 environments | `Postponed` | Not started |
| ~~**TODO-VA-04**~~ | `LOW` | **Implement Variadic Templates Helper Function**<br><br>- Implement C++11 Variadic Templates-based `make_valist` helper function | `Won't Fix` | Existing code in sprintf.hpp |

---
