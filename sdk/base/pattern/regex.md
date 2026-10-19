## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Regular expressions

## 1. Role

`regex.hpp` and `regex.cpp` provide hotplace's regular-expression wrapper/context. The selected backend depends on the project's build configuration; this page does not assume one backend is active in every build.

## 2. Model

```text
pattern + input text
        |
        v
hotplace regex wrapper/context
        |
        v
configured regex backend
        |
        v
match result / captures as exposed by API
```

Regex matching is distinct from the wildcard API. A caller should use the syntax and result contract of the specific wrapper, rather than assume every backend behaves identically in all edge cases.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source tests

`testvector_regex.cpp` and `testvector_regex.yml` provide regex test vectors. The base report lists 80 pass entries in the `regular expression` group. `sdk/io/string/url.cpp` is a repository call site that uses the regex facility to decompose URL components.

## 5. Relationships

- `sdk/base/pattern/regex.hpp`
- `sdk/base/pattern/regex.cpp`
- `test/testcase/base/pattern/testvector_regex.cpp`
- `test/testcase/base/pattern/testvector_regex.yml`
- `sdk/io/string/url.cpp`

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
