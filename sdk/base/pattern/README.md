## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Pattern

## 1. Role

`sdk/base/pattern` groups independent sequence-matching and text-indexing implementations. The commonality is that they operate on sequences; they do not share one interchangeable search interface or one common complexity profile.

## 2. Data Model

### Shared element access

`pattern.hpp` defines the common element-access and comparison helpers used by the templates:

- `memberof_defhandler<BT, T>` reads an element from a sequence and converts it to the algorithm's comparison type `BT`.
- A custom `memberof` functor lets algorithms work on objects or pointers by extracting a comparable symbol, such as a token type.
- `t_comparator_base` provides a comparator wrapper; KMP accepts its own equality comparator.

This makes the algorithms usable with byte/character arrays and token-like sequences, provided the caller supplies a compatible element-access handler.

### Algorithm families

| Implementation | Stored representation | Primary operation |
|---|---|---|
| [KMP](kmp.md) | One learned pattern and its failure table | Find the first occurrence of one pattern |
| [Trie](trie.md) | Prefix nodes with child links, terminal markers, indices and optional tags | Exact lookup, prefix lookup, longest-prefix scan |
| [Aho-Corasick](aho_corasick.md) | Trie nodes with failure links and output pattern IDs | Find occurrences of many patterns in one pass |
| [Suffix trie and Ukkonen](suffix-tree-ukkonen.md) | A suffix trie, plus a separate compressed suffix-tree construction | Index a source sequence for substring queries |
| [Wildcard matching](wildcard.md) | A pattern interpreted using configurable one-element and zero-or-more wildcards | Match one wildcard expression |
| [Regular expressions](regex.md) | A compiled regex context backed by the selected regex implementation | Find regex matches and return source ranges/captures |

The suffix-related pair is intentionally distinguished: `t_suffixtree` expands every suffix into a trie-like structure, while `t_ukkonen` stores edge intervals and suffix links for an incrementally constructed compressed suffix tree.

### How to choose the matching model

```text
Sequence matching / indexing
├── One known pattern ───────────────► KMP
├── Many known patterns ─────────────► Aho-Corasick
│                                      ├── optional wildcard extension
│                                      └── token/sub-pattern reducer
├── Stored keys or prefixes ─────────► Trie
├── Substring index ─────────────────► suffix trie or Ukkonen tree
└── Pattern language
    ├── one wildcard expression ─────► standalone wildcard matcher
    └── regular-expression syntax ───► regex context
```

This is a problem-shape map, not an inheritance diagram: the algorithms have separate APIs and state models. Only the wildcard-aware matcher and reducer are implemented as extensions of Aho-Corasick.

## 3. Behavior Model

The algorithms differ in when they preprocess and what they return:

- **Preprocess then query:** KMP's `learn()` builds a failure table; Aho-Corasick's `insert()` collects patterns and `build()` computes failure links; regex contexts compile an expression before repeated searches.
- **Incremental dictionary/index operations:** Trie supports adding and removing keys, exact membership, prefix queries and longest-match scanning. The suffix trie and Ukkonen structure are built from source sequences and return occurrence positions.
- **Interpretation during matching:** Standalone wildcard matching uses caller-selected wildcard symbols. Aho-Corasick's wildcard subclass integrates wildcard transitions into multi-pattern search; it is not the same implementation as `t_wildcards`.
- **Higher-level token reduction:** `aho_corasick_reducer.hpp` extends the automaton with virtual token groups, sub-pattern rules, repeat rules and block reduction. This is a bridge between token matching and parser-oriented structure, not a generic parser.
- **Backend-dependent matching:** Regex behavior is selected at compile time. In the current source, older GCC builds use PCRE because the project's supported legacy toolchain cannot rely on a working `std::regex` implementation; newer GCC and MSVC use `std::regex`.

## 4. Relationships

- `sdk/io/parser/` — consumes token-oriented pattern/reduction behavior; the Aho-Corasick reducer can collapse token sequences into higher-level virtual tokens.
- `sdk/base/encoding/huffman_coding.*` — uses Trie longest-prefix scanning to decode variable-length Huffman codes.
- `sdk/io/basic/oid_dictionary.*` — uses Trie exact lookup over numeric OID arcs, with terminal metadata attached as a tag.
- `sdk/io/string/url.cpp` — uses the regex helpers to decompose URL components.
- `test/testcase/base/pattern/` — owns source-level testcase descriptions and report-derived verification context; see [pattern testcase overview](../../../test/testcase/base/pattern/README.md).
- Algorithm-specific details are documented in the linked pages above.
