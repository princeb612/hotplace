# `t_range_set` & `t_interval` - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: C++11 Template-based Range Set module designed to efficiently perform Merge, Subtract, Intersect, and Union operations on discrete or overlapping intervals in QUIC ACK Ranges, memory segment management, and numerical range calculations.
* **Key Features**:
  * **Type-Specific Merge Specialization (`range_traits`)**:
    * Discrete Integer Types: Automatically merges adjacent consecutive values (`current.end + 1 >= next.begin`).
    * Continuous (Floating Point) & Custom Types: Supports precise merging through boundary condition checks using open (`open` / `( )`) and closed (`closed` / `[ ]`) flags.
  * **Infinite Range Representation (`t_range_value`)**: Supports infinite range operations via `minvalue` ($-\infty$) and `maxvalue` ($+\infty$).
  * **Set Operations and Inversion Support**:
    * Provides Union (`union_with`), Difference (`erase_from`), and Intersection (`intersect_with`) operations.
    * Supports complement (All-Except / Inverted Range) condition representation using the `invert()` toggle.
  * **Thread Safety**: Internally utilizes `critical_section` and `critical_section_guard` to ensure data consistency in concurrent environments.

---

### 2. Core Implementation Areas and Technical Elements

* **Interval Trait Abstraction**: Decouples integer and floating-point data type properties into the `range_traits` structure to optimize interval adjacency boundary checks.
* **Boundary Condition Handling**: Introduces boundary flags (`open`, `closed`) to eliminate calculation ambiguity between continuous and mutually exclusive intervals.
* **Concurrency Protection**: Applies the Single Entry/Exit Guard pattern during operations for thread-safe collection management.

---

### 3. Major Data Structures/Classes and API Structure

**Key Enumerations and Structures**

```cpp
enum class range_type_t : int8 { minvalue = -1, value = 0, maxvalue = 1 };
enum class range_flag_t : uint8 { open = 0, closed = 1 };

template <typename T>
struct t_interval {
    T begin;
    T end;
    range_flag_t begin_flag;
    range_flag_t end_flag;
};

```

**Major Class and API Structure (`hotplace::t_range_set<T>`)**

| Class / Method | Role and Functionality |
| --- | --- |
| **`t_range_set<T>`** | Range interval set management class. |
| `add(start, end)` | Adds a range by specifying start and end points (supports `t_interval`, `t_range_set`). |
| `subtract(start, end)` | Removes a specific range via set subtraction operation (automatically readjusts boundary flags). |
| `intersect(other)` | Extracts common intersection with another `t_range_set`. |
| `merge()` | Sorts internal intervals and completely merges overlapping/adjacent intervals into one before returning. |
| `has(value)` / `has(interval)` | Verifies whether a value or a specific interval is contained. |
| `union_with(other)` | Set union operation considering inversion state. |
| `erase_from(other)` | Set difference operation considering inversion state. |

---

### 4. Core Operating Mechanism

* **Interval Sorting & Merging Mechanism**: Ranges added via `add()` are pushed into an internal vector storage, then sorted (`std::sort`) and collapsed into unified `t_interval` entries upon calling `merge()`.
* **Boundary Adjustments during Subtraction**: When executing `subtract()`, existing intervals lying within the targeted range are split into two, with boundary attributes (`open` / `closed`) inverted to guarantee mathematical set difference accuracy.
* **Inverted Range Operations**: When inversion mode (`_invert = true`) is active, internal membership evaluation logic is reversed, enabling efficient tracking of subtracted allocations inside an otherwise infinite memory space.

---

### 5. Usage Example (C++11 Standard)

```cpp
#include <iostream>
#include <hotplace/sdk/base/nostd/range_set.hpp>

// Single Exit Point Macro definition
#define __try2 do {
#define __finally2 } while(0);
#define __leave2 break;

int main() {
    int ret = 0;

    __try2
        using namespace hotplace;

        // 1. Integer Range Set Example (Discrete values)
        t_range_set<uint64> ack_ranges;

        // Add overlapping or consecutive packet numbers
        ack_ranges.add(1, 5)
                  .add(6, 10)   // Automatically merges with [1, 5] -> [1, 10]
                  .add(14, 18)
                  .add(21);     // Single point range [21, 21]

        std::cout << "[ACK Ranges Merge Result]\n";
        auto merged = ack_ranges.merge();
        for (const auto& item : merged) {
            std::cout << "Range: [" << item.begin << ", " << item.end << "]\n";
        }

        // 2. Floating Point & Infinite Range Example
        using fp_range_set = t_range_set<t_range_value<float>>;
        using fp_interval  = t_interval<t_range_value<float>>;

        fp_range_set float_ranges;

        // Add [-inf, -1.0] and [1.0, 4.0], then subtract [1.5, 3.5]
        float_ranges.add(range_type_t::minvalue, -1.0f)
                    .add(1.0f, 4.0f)
                    .subtract(1.5f, 3.5f);

        std::cout << "\n[Float Range Subtract Result]\n";
        float_ranges.for_each2([](const fp_interval& item) {
            char left_bracket  = (item.begin_flag == range_flag_t::closed) ? '[' : '(';
            char right_bracket = (item.end_flag == range_flag_t::closed) ? ']' : ')';

            std::cout << "Range: " << left_bracket;
            if (item.begin.type == range_type_t::minvalue) std::cout << "-INF";
            else std::cout << item.begin.value;

            std::cout << ", ";

            if (item.end.type == range_type_t::maxvalue) std::cout << "+INF";
            else std::cout << item.end.value;

            std::cout << right_bracket << "\n";
        });

        // Point check
        std::cout << "\nContains 1.2f: " << (float_ranges.has(1.2f) ? "true" : "false") << "\n";
        std::cout << "Contains 2.0f: " << (float_ranges.has(2.0f) ? "true" : "false") << "\n";

        if (false) {
            ret = -1;
            __leave2;
        }

    __finally2

    return ret;
}

```

---

### 6. TODO list

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| ~~TODO-RS-01~~ | `HIGH` | **Tuning `merge_internal` sorting and merging algorithm**<br><br>- Consider applying Insertion Sort instead of a full `std::sort` call when inserting small datasets or into already sorted states | `Open` | Performance improvement for `merge_internal()`<br> |
| ~~TODO-RS-02~~ | `HIGH` | **Minimize `critical_section` lock scope during `subtract` and `intersect` operations**<br><br>- Consider fine-grained locking to release lock early during temporary object creation | `In Progress` | Reduce thread contention |
| ~~TODO-RS-03~~ | `MEDIUM` | **Support C++11 `std::initializer_list**`<br><br>- Add initializer list constructor and insertion APIs like `add({ {1, 5}, {6, 10} })` | `Open` | Extend convenience |
| ~~TODO-RS-04~~ | `MEDIUM` | **Write comprehensive unit tests for Inverted Set (`_invert`) symmetry**<br><br>- Enhance test coverage for 4 De Morgan combination conditions among `union_with`, `erase_from`, and `intersect_with` | `In Progress` | Verification via `_test_case`<br> |
| ~~TODO-RS-05~~ | `LOW` | **Refactor C++11 template comparison operators in `t_range_value**`<br><br>- Resolve potential compiler warnings during type conversions and complete English comment documentation | `Open` | Header documentation |
