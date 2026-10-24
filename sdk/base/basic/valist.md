## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Dynamic `va_list`

## 1. Role

### Introduction

`valist` provides a dynamically constructed `va_list` for code that needs to collect arguments before passing them to an existing variadic interface.

Arguments are stored as `variant_t` values. When `get()` is requested, the implementation builds the platform-specific native `va_list` representation from those stored values.

## 2. Data Model

### Stored arguments and native view

Each insertion is normalized into a `variant_t` and appended to the ordered `_args` vector. This vector is the retained argument model: it preserves each argument's type/value metadata and its position for the formatter's 1-based references. `at()` and `operator[]` expose stored values by index; `clear()` removes the stored sequence and releases the constructed native view.

The native representation is held separately in `_va_internal` and exposed through the `valist_t` union as the platform's `va_list` view. `_modified` records that the stored arguments have changed and the native representation must be rebuilt. The internal critical section protects list operations; it does not make a native `va_list` portable across ABIs.


## 3. Behavior Model

### ABI and argument promotions

The implementation normalizes several C/C++ argument promotions before constructing the native representation. This is important because a `va_list` cannot be treated as a portable pointer-like object.

A native `va_list` has compiler- and architecture-specific representation. The implementation includes distinct handling for supported GCC/Linux and Microsoft compiler environments; the GCC x86-64 path accounts for the register-save and overflow-area model rather than assuming that arguments form a simple stack array.

Argument promotions and exact widths matter. The stored `variant_t` values must be mapped to the representation expected by the receiving variadic function. Treating `va_list` as a portable pointer or copying its internals across ABIs is unsafe.

### Rebuild and consumption flow

Appending an argument changes `_args` and marks the native view modified. A call to `get()` requests the native view; if the stored sequence changed, `build()` reconstructs it for the active compiler/architecture. The consumer then uses that view for the duration of a compatible variadic call. Any subsequent append, clear, or reassignment can invalidate the correspondence between the stored sequence and the already-built native view, so consumers should reacquire it after mutation.

```text
operator<< / append
  └─ normalize to variant_t → append to _args → mark native view modified
get()
  └─ if modified → build ABI-specific va_list → expose native view
formatter / variadic consumer
  └─ consume according to its argument types and format syntax
```

### Hotplace format-string syntax

The format-string parser refers to stored arguments by **1-based position**. The order in the format string can differ from insertion order.

```text
{1:02x}  {1:3d}  {2:-10s}
```

The text after `:` is a type-specific format specifier. The examples show numeric formatting/width and a left-aligned string field; the formatter interprets the specifier according to the stored argument type.

For `binary_t` (`TYPE_BINARY`):

- `s` emits one character per byte when printable; non-printable bytes become `.`. This is a readable diagnostic view, not a lossless representation.
- `x` emits Base16/hexadecimal text; `X` uses uppercase hexadecimal digits.

For integer arguments, `x` / `X` use the formatter's `0x`-prefixed hexadecimal form, while `h` emits hexadecimal digits without the `0x` prefix.

These are `sprintf()` format semantics, not conversions performed when `valist` stores a value: `valist` retains the typed argument and the formatter applies the specifier later.

### Value-to-call flow

```text
append typed values
  └─ store each value as variant_t
       ├─ retain type / size / flags / value representation
       └─ preserve argument order

build native argument view
  └─ map stored values to the selected compiler/architecture ABI
       ├─ register-save area / overflow area where required
       └─ native variadic-call representation

formatter consumes arguments
  └─ parse 1-based {position:specifier} fields
       └─ apply formatting specifier according to stored type
```

`valist` storage and formatting are separate phases: a format specifier does not change the stored value's type. Native `va_list` reconstruction is ABI-specific, so a change to its layout handling must be reviewed against each supported compiler/architecture rather than inferred from a single platform.

### Practical use: format typed arguments from a vector

The YAML-driven testcase converts each declared argument to its intended C++ type before inserting it into `valist`. One vector supplies an integer, a string, and a floating-point value; the formatter can reuse or reorder those values by their 1-based positions:

```cpp
valist va;
va << 256 << "hello world" << 3.141592f;

basic_stream bs;
sprintf(&bs, "value={1}, value={1:04x}, value={1:04d}", va);
// expected: value=256, value=0x0100, value=0256
_test_case.assert(bs == "value=256, value=0x0100, value=0256",
                  __FUNCTION__, "typed arguments");
```

The format specifier changes the textual presentation, not the stored value. The testcase also permutes argument references (for example, `{2} {3} {1}`) and includes ABI-sensitive integer widths, making it useful to distinguish format behavior from native variadic argument construction.

## 4. Relationships

- `variant_t` is the intermediate typed-value representation; `valist` adapts stored values to the native variadic calling convention.
- The adapter is general-purpose; `sprintf()` is one consumer of `valist`. `basic_stream::vaprintf()` and `basic_stream::vaprintln()` are convenience entry points that forward to the formatter, not the definition of the `valist` abstraction.
- `test/testcase/base/basic/testcase_valist.cpp`, `testvector_valist.cpp`, and `testvector_valist.yml` provide source-level coverage for the adapter and formatting paths.
- `valist` is ABI-sensitive; do not infer portability from the high-level `operator<<()` interface alone. The adapter is implemented in `valist.hpp/.cpp`, uses `variant.hpp` as its intermediate representation, and is exercised by `testcase_valist.cpp`.
