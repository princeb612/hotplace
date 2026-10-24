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

# Standalone wildcard matching

## 1. Role

`t_wildcards` matches one input sequence against one wildcard expression. The caller chooses the symbol for “exactly one element” and the symbol for “zero or more elements.” This is intentionally simpler than the multi-pattern wildcard extension built on Aho-Corasick.

## 2. Data Model

The class stores `_wild_single`, `_wild_any` and the `memberof_t` element extractor. It does not build a trie, failure links or a compiled pattern object. Its template parameters allow matching characters, token enums or pointer-based token objects.

The input and pattern elements are compared after passing through `memberof`. Wildcard markers are interpreted in that normalized comparison domain, so callers must choose marker values that do not collide with ordinary symbols they need to match literally.

## 3. Behavior Model

**`match()`**

Advances input and pattern positions when the current pattern symbol is the single-element wildcard or equals the current input symbol.

**Handling the zero-or-more wildcard**

When the pattern reaches `_wild_any`, the matcher remembers that wildcard's position and the current input position, then attempts to match the remainder of the pattern. If a later symbol mismatches, it returns to the remembered wildcard and expands it by one input element.

**Completion**

After the input is consumed, trailing zero-or-more wildcards may be skipped. The match succeeds only if the pattern is then exhausted. This is a greedy backtracking strategy centered on the most recently encountered `*`; it does not expose captures or implement regular-expression syntax.

The longest-common-prefix helper found in the testcase is test-local code, not part of `t_wildcards`.

### Practical example: match a filename-like pattern

```cpp
std::string text = "baaabab";
t_wildcards<char> wild('?', '*');

bool matches = wild.match(text.c_str(), text.size(), "ba?a*b", 6); // true
bool rejected = wild.match(text.c_str(), text.size(), "ba?ab?c", 7); // false
```

Here `?` matches exactly one character and `*` matches zero or more characters. The first pattern can match the input by letting `?` consume `a` and `*` consume the remaining middle characters; the second requires a final `c` that the input does not have. This follows `test_wildcards1()` in `testcase_wildcard.cpp`. The API reports only whether the whole input matches; it does not return captures.

### Source flow: greedy expansion of the most recent `*`

```text
input cursor i, pattern cursor p
  ├─ literal equal or `?` ─► i++, p++
  ├─ `*` ──────────────────► remember star position and current i; p++
  ├─ mismatch with saved `*` ─► restore p after `*`; expand saved match by i++
  └─ mismatch without saved `*` ─► fail

input exhausted
  └─ skip trailing `*` ─► success only if pattern exhausted
```

The saved wildcard is a backtracking checkpoint, not a set of active automaton states. When a later literal fails, the matcher gives the latest `*` one more input element and retries the remaining pattern. This keeps the implementation small, but it is a different search strategy from the queue of active states used by `t_aho_corasick_wildcard`.

## 4. Relationships

- `pattern.hpp` — default/custom element extraction.
- `aho_corasick.md` — explains why multi-pattern wildcard matching needs active-state exploration and additional range metadata.
- `test/testcase/base/pattern/testcase_wildcard.cpp` — character and token/pointer matching.
- `test/testcase/base/pattern/testcase_aho_corasick_wildcard.cpp` — wildcard matching across multiple registered patterns.

## 5. References

- [Wildcard pattern matching](https://www.geeksforgeeks.org/wildcard-pattern-matching/?ref=lbp)
