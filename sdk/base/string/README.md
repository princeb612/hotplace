# Base String

`sdk/base/string` contains general-purpose string scanning, formatting, splitting and replacement helpers, plus the project's string-obfuscation experiments.

This is the general string layer; `sdk/io/string` is the I/O/protocol-facing string layer.

## Documents
- [string](string.md) — scan, getline, replace, formatting and token helpers
- [split](split.md) — reusable split context and iteration API
- [obfuscation](obfuscation.md) — runtime and C++14 constexpr obfuscation experiments

## Related tests
- `test/testcase/base/string/testcase_string.cpp`

## Source
- `sdk/base/string/`
