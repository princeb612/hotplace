## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Knuth–Morris–Pratt (KMP)

## 1. Role

`kmp.hpp` implements single-pattern searching using the Knuth–Morris–Pratt algorithm. Unlike Aho-Corasick, it searches for one pattern per invocation rather than matching a set of patterns through one automaton.

## 2. Model

```text
text + pattern
      |
      v
prefix/failure information
      |
      v
scan without restarting from the beginning after each mismatch
      |
      v
match position or no-match result
```

The precise return convention and type-specific behavior should be read from the overload used by the caller.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source tests

`testcase_kmp.cpp` checks byte-oriented matching and generic element types, including a custom struct and a pointer type with a comparator. The expected match position in these cases is asserted to be `0xa`.

## 5. Relationships

- `sdk/base/pattern/kmp.hpp`
- `test/testcase/base/pattern/testcase_kmp.cpp`
- `test/testcase/base/pattern/testvector_kmp.cpp`
- `test/testcase/base/pattern/testvector_kmp.yml`

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
