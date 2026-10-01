# Wildcard and Regex

`wildcard.hpp` implements wildcard matching and the associated longest-common-prefix behavior exercised by the wildcard testcase.

`regex.hpp/.cpp` provide the project's regular-expression wrapper/context. The implementation can use the project's configured regex backend; `sdk/io` links the corresponding backend when the non-standard regex path is selected.

## Usage in hotplace

These utilities are general pattern facilities. For example, `sdk/io/string/url.cpp` uses the regex facility to decompose URL components. The parser-oriented Aho-Corasick reducer is a different layer and should not be conflated with regex matching.

## Tests

- `testcase_wildcard.cpp`
- `testvector_regex.cpp`
- `testvector_regex.yml`
