# Aho-Corasick & Wildcard

## 1. Class Hierarchy and Separation of Responsibilities

A core C++ library structure for supporting multi-pattern matching and a higher-level parser that handles wildcards in a C++11 environment.

```text
┌──────────────────────────────────────────────────────────┐
│  t_aho_corasick_t<BT, T>                                 │ (pure virtual interface class)
└─────────────────────────────┬────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────┐
│  t_aho_corasick<BT, T, memberof_t>                       │ (basic Aho-Corasick algorithm)
└─────────────────────────────┬────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────┐
│  t_aho_corasick_wildcard<BT, T, memberof_t>              │ (single/arbitrary wildcard extension)
└──────────────────────────────────────────────────────────┘
```

---

## 2. Core Mechanism of the Basic Engine (`t_aho_corasick`)

### ① `trienode` Structure Design

* **`children`**: A map of child trie nodes used for exact key-value matching.
* **`group_children`**: A trie-node map reserved in advance for future extensions to group matching when integrating with a parser.
* **`failure`**: The Failure Link to fall back to when a search fails. This is a core mechanism of the Aho-Corasick algorithm.
* **`output`**: A set of pattern IDs (`std::set<size_t>`) that terminate at the current node.

### ② Three-Stage Algorithm Life Cycle

1. **`doinsert()`**: Register patterns

   * Traverse the input sequence, create trie nodes as necessary, and add the pattern ID to the `output` set of the pattern's final node.

2. **`dobuild()`**: Build Failure Links and merge Outputs (BFS)

   * Construct the Failure Links of each node using breadth-first search (BFS).
   * Merge the `output` list of the node pointed to by the Failure Link into the current node's `output` list.

3. **`dosearch()` / `collect_results()`**: Search the text and collect results

   * Scan the source stream once in **O(N)** time, transition through the trie states, and collect the ending position and pattern ID in the result map whenever a match occurs.

---

## 3. Wildcard Extension Engine (`aho_corasick_wildcard`)

Core extension logic for supporting both single-character wildcards (`?`, `flag_single`) and variable-length string wildcards (`*`, `flag_any`).

### ① Switching to a BFS-Based Search Queue (`std::queue`)

The basic `t_aho_corasick` performs a search using a single loop. However, because searching for the wildcard `*` can generate multiple branching paths, `dosearch` is reimplemented using a breadth-first search approach based on **`std::queue<pair_t>`** and a visited-state map (`visit`) to track these branching paths.

### ② `_hidden` Tag Technique for Adjusting the Starting Position

Aho-Corasick has a limitation in that it returns only the **ending position** of a matched pattern.

For a variable-length pattern such as `h*s`, the starting position must be determined by tracking the prefix—the hidden pattern—located before the first wildcard `*`.

* **`baseof_prefix` (`0x10000000`)**: A virtual pattern ID offset used for prefixes preceding a wildcard.
* **`hidden_tag_t`**:

  * **`size`**: Length of the prefix preceding the wildcard.
  * **`adjust`**: Number of actual fixed pattern characters excluding the wildcard (`lengthof(pattern) - lengthof(wildcard_any)`).
  * **`modes`**: Adjustment flags for `*pattern` (startswith) and `pattern*` (endswith) forms.

### ③ Wildcard Range Calculation (`get_result`)

1. When registering the pattern `hello*world`, register `hello` as a virtual prefix pattern (`PID + 0x10000000`) to trigger prefix matching.
2. During the search, when the ending position of `world` (`Pos_end`) is detected, find the nearest occurrence of `hello` whose position is less than or equal to `Pos_end - Adjust + 1` from the stored prefix-position list using `find_lessthan_or_equal`.
3. Restore the exact matching range as `range_t(begin, end)`.

---

## 4. Usage Pattern Snippets Based on the Source Code

### ① Flexible Type Conversion Handler (`memberof_t`)

Through template metaprogramming, `t_aho_corasick` can search not only simple strings (`char`) but also pointer-based structures or token-stream arrays.

```cpp
// Example of a member extraction functor that obtains the type field
// from an array of token object pointers.
struct token { int type; };

auto memberof = [](token* const* source, size_t idx) -> int {
    const token* p = source[idx];
    return p->type;
};

// Construct an Aho-Corasick instance for a token* array.
t_aho_corasick<int, token*> ac(memberof);
```

### ② Simultaneous Ignore-Case and Wildcard Support

```cpp
// Apply memberof_tolower_handler to perform case-insensitive matching.
t_aho_corasick_wildcard<char, char, memberof_tolower_handler> ac('?', '*');

ac.insert("we *ing", 7);
ac.insert("we * old", 8);
ac.build();

const char* source = "We don't playing because we grow old;";
auto result = ac.search(source, strlen(source));
```

---

## 5. C++11 Implementation Characteristics and Refactoring Notes

1. **Replacing `std::function` with Functors (Revision 1003, 2026.05.19)**

   * To reduce runtime overhead caused by lambda/`std::function` calls and virtual function calls, the implementation was changed to a functor-based structure using the template parameter `memberof_t`, encouraging compile-time inlining.

2. **Use of `std::multimap` and Hash Functions**

   * For syntax comparison, an `equal()` template function is provided using an `unordered_multiset` based on the custom hash function `universal_pairhash`.

3. **Considerations Regarding Queue-Based Search Overhead (Comment #4)**

   * When searching large amounts of data, memory may accumulate in the `q` and `visit` structures used to prevent duplicate queue entries. There is still room for optimization by continuously pruning `visit` records corresponding to text ranges that have already been processed.
