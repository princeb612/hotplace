# `t_cmdline_t` & `t_cmdarg_t` - published by Gemini

## 1. Overview & Key Features

The `cmdline.hpp` module is a C++11 template-based parser designed to handle Command Line Arguments in a type-safe and intuitive manner.

* **Custom Option Structure Binding**: Takes a custom struct/class template (`T`) as a type parameter and directly binds the parsing results to an instance of that type.
* **Fluent Interface & Move Semantics**: Leverages the `<<` operator along with move constructors and move assignment operators to enable clear, chained option registration.
* **Optional/Required & Parameter Flag Control**:
  * `preced()`: Specifies an option that must be followed by a value parameter (e.g., `-in FILENAME`).
  * `optional()`: Specifies an optional parameter (options are treated as required by default if not set).
* **ANSI Color-Supported Help Output**: Provides visual guidance (`help()`) on the terminal screen by distinguishing required options and parsing statuses.

---

## 2. Key Implementation Areas & Technical Elements

* **Move Semantics-Based Chaining**: Actively utilizes `rvalue` references and move semantics to prevent unnecessary copying during option object creation and registration, enabling a Fluent Interface.
* **Callback Binding**: Binds execution logic for each parsed argument using `std::function` lambda expressions, decoupling the parser from user-defined data structures.
* **Strict Validation**: Validates missing mandatory options, duplicate token registrations, and missing trailing values (`preced`) during the parsing phase, returning error codes accordingly.

---

## 3. Major Data Structures, Classes & API Reference

### Flag Definitions

```cpp
enum cmdline_flag_t : uint32 {
    cmdline_preced   = (1 << 1),  // Expects a value in the next token
    cmdline_optional = (1 << 2),  // Optional parameter
};

```

### Core Classes & Methods

| Class / Method | Description & Functionality |
| --- | --- |
| **`t_cmdarg_t<T>`** | Class defining an individual command line option. |
| `t_cmdarg_t(token, desc, func)` | Registers option token name, description, and binding callback lambda (`std::function`). |
| `.preced()` | Specifies that the argument requires a subsequent value parameter. (Supports `lvalue` / `rvalue` method chaining). |
| `.optional()` | Marks the option as optional. (Treated as mandatory if not invoked). |
| **`t_cmdline_t<T>`** | Class managing the option collection and executing parsing. |
| `operator<<(t_cmdarg_t&&)` | Registers an option object via move construction (throws an exception on duplicate tokens). |
| `parse(argc, argv)` | Iterates through command line arguments, invokes registered lambdas, and verifies missing required options. |
| `value()` | Returns a constant reference to the parsed result object of type `T`. |
| `help()` | Outputs registered option list and help text as formatted text. |

---

## 4. Operational Principles

1. **Option Registration Phase**: Registers `t_cmdarg_t` instances into the parser object (`t_cmdline_t`) using `operator<<`. Custom lambda callbacks and flags are stored by token in an internal container/map.
2. **Parsing & Traversal Phase (`parse`)**: Iterates through `argc` and `argv` to verify matching tokens.
  * If the `preced` flag is set, the subsequent token is extracted as a parameter value and passed to the bound lambda callback.
  * If a required option (without the `optional` flag) is missing from `argv`, a parsing error code is returned.
3. **Result Collection**: The user-defined structure `T` is populated through callbacks executed during parsing, and the final result can be retrieved via `value()` upon successful parsing.

---

## 5. Usage Example (C++11 Standard)

```cpp
#include <iostream>
#include <hotplace/sdk/base/basic/cmdline.hpp>

// Program option structure
struct program_options {
    std::string input_file;
    std::string output_file;
    bool generate_key;

    program_options() : generate_key(false) {}
};

int main(int argc, char** argv) {
    using namespace hotplace;

    // Create command line parser instance
    t_cmdline_t<program_options> cmdline;

    try {
        // Register arguments using operator<< and rvalue move-chaining
        cmdline
            << t_cmdarg_t<program_options>("-in", "Specify input file path",
                [](program_options& opt, const char* param) -> void {
                    opt.input_file = param;
                }).preced()
            << t_cmdarg_t<program_options>("-out", "Specify output file path",
                [](program_options& opt, const char* param) -> void {
                    opt.output_file = param;
                }).preced().optional()
            << t_cmdarg_t<program_options>("-keygen", "Generate security key",
                [](program_options& opt, const char* param) -> void {
                    opt.generate_key = true;
                }).optional();

        // Parse command line arguments
        return_t ret = cmdline.parse(argc, argv);

        if (errorcode_t::success != ret) {
            std::cout << "[Warning] Invalid command line arguments!\n\n";
            cmdline.help();
            return ret;
        }

        // Retrieve parsed result
        const program_options& opt = cmdline.value();
        std::cout << "[Config] Input file  : " << opt.input_file << "\n";
        std::cout << "[Config] Output file : " << opt.output_file << "\n";
        std::cout << "[Config] Keygen mode : " << (opt.generate_key ? "ENABLED" : "DISABLED") << "\n";

    } catch (const exception& e) {
        std::cerr << "[Error] Exception caught: " << e.what() << "\n";
        return e.get_code();
    }

    return errorcode_t::success;
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| ~~TODO-CL-01~~ | `HIGH` | **Inspect GCC 4.8.5 `noexcept = default` compatibility**<br><br>- Test whether workarounds for `GCC 4.8.5 bug` in header comments can be removed and complement C++11 standard compliance. | `Won't Fix` | Move constructor/assignment operator |
| ~~TODO-CL-02~~ | `HIGH` | **Review duplicate option input handling policy**<br><br>- Add selectable policy between overwrite/error return when duplicate options are passed via command line. | `Won't Fix` | Existing `duplicate` handling is standard policy |
| **TODO-CL-03** | `MEDIUM` | **Support Short/Long option aliasing**<br><br>- Review supporting alias token binding functionality like `-i` / `--input`. | `To Do` | Refactor `_args` map structure |
| **TODO-CL-04** | `MEDIUM` | **Diversify `help()` output formatting and improve line break handling**<br><br>- Provide switch flag for environments unable to use ANSI escape codes (e.g., legacy Windows). | `To Do` | Console API integration |
| ~~**TODO-CL-05**~~ | `LOW` | **Clean up destructor and virtual function structures**<br><br>- Review explicit Virtual Destructor specification based on inheritance of `t_cmdline_t` and `t_cmdarg_t` classes. | `Fixed` | Marked as final |

---
