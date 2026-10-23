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

# Knuth–Morris–Pratt (KMP)

## 1. Role

`t_kmp` searches for one pattern in a sequence. It avoids restarting the text scan at every mismatch by retaining how much of the pattern can still match.

## 2. Data Model

- `T` is the source/pattern element type.
- `comparator_t` determines whether two elements are equivalent. A custom comparator is useful when input elements are objects or pointers and comparison should use a field rather than pointer identity.
- `_pattern` stores the learned pattern.
- `_failure` stores the prefix/failure table used to reuse a matching prefix after a mismatch.
- `npos` is `size_t(-1)`, the not-found result.

The comparator is retained by the matcher and used both when building the failure table and when scanning the source.

## 3. Behavior Model

**`learn(pattern)`**

Copies the pattern into the matcher and builds `_failure`. Each entry records how much of the already-matched prefix can be reused when the next comparison fails. The table is reusable across multiple searches for the same pattern.

**`search(data)`**

Scans the source while tracking the current pattern position. On a match, both positions advance. On a mismatch with a nonzero pattern position, the matcher jumps to the reusable prefix specified by `_failure`; it does not move the source position backward. If the mismatch occurs at pattern position zero, the source position advances.

Returns the starting index of the first occurrence, or `npos` when no occurrence is found.

**`search(data, pattern, pos)`**

Learns the supplied pattern and searches the source beginning at `pos`. The `pos` value is a source offset, not a pattern offset.

The intended time complexity is (O(n+m)) for source length (n) and pattern length (m), including failure-table construction. Callers should provide a non-empty pattern rather than relying on unspecified empty-pattern behavior.

### Source flow: build once, reuse for each scan

```text
learn(pattern)
  ├─ copy pattern into _pattern
  └─ build _failure
       └─ for each pattern position, retain the longest proper prefix
          that is also a suffix of the prefix already examined

search(data)
  ├─ compare data[i] with _pattern[j]
  ├─ equal ───────────────► i++, j++
  ├─ mismatch and j > 0 ──► j = _failure[j - 1], keep i
  └─ mismatch and j == 0 ─► i++
       └─ j == pattern length ─► return first match start
```

The important state transition is the mismatch branch: the source cursor `i` does not retreat. Only the pattern cursor `j` falls back through the failure table. The implementation therefore reuses comparisons already implied by the matched prefix instead of rescanning the same source region.

## 4. Relationships

- `pattern.hpp` — shared element-access conventions; KMP's equality comparator is specific to `t_kmp`. The implementation is in `kmp.hpp`.
- `test/testcase/base/pattern/testcase_kmp.cpp` — asserts match index `0xa` for byte vectors, contiguous memory, value objects and pointer objects with a custom comparator.
- `test/testcase/base/pattern/testvector_kmp.cpp` and `testvector_kmp.yml` — additional vector-driven cases.
- `sdk/io/parser/` — related parser pattern-search APIs, but not the same class as `t_kmp`.

## 5. References

- *Data Structures & Algorithms*, Section 12.3.3, “The Knuth–Morris–Pratt Algorithm” — the source header cites this section for the failure-function and linear-time matching algorithm.
