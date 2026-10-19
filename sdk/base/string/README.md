## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Base String

## 1. Role

### Introduction

`sdk/base/string` provides general-purpose string and bounded-buffer helpers used by SDK code. It contains scanning and line/token extraction, formatting and replacement, delimiter splitting, string wrapper types, and two distinct obfuscation facilities.

This is the general base layer. It is separate from `sdk/base/stream` (stream-oriented output and buffering) and `sdk/io/string` (I/O/protocol-facing string handling).

## 2. Model

The component model is described by the implementation and retained subsections below.

## 3. Important behavior and lifetime

### Documents

- [String utilities](string.md) — `format`, `replace`, `scan`, `getline`, token helpers, and string wrappers
- [Split context](split.md) — delimiter splitting with source-relative ranges
- [String obfuscation](obfuscation.md) — runtime `obfuscate_string` and its output conversions
- [Compile-time obfuscation](constexpr-obfuscation.md) — the C++14+ `constexpr_obfuscate` facility

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

Related components and cross-module links are listed in References where available.

## 6. References

### Related source and tests

- Implementation: `sdk/base/string/string.hpp`, `split.hpp/.cpp`, `format.cpp`, `string_charset.cpp`, `obfuscate_string.hpp/.cpp`, `constexpr_obfuscate.hpp`
- Test source: [`testcase_string.cpp`](../../../test/testcase/base/string/testcase_string.cpp)
- Test notes and report: [`testcase_string.md`](../../../test/testcase/base/string/testcase_string.md)

The authoritative API and behavior for this revision are the declarations and implementation in this directory. Test examples below are derived from the listed testcase source; test execution status is documented separately from source-level assertions.

### Source basis

Edition 1 · Revision 1104
