# Pattern Search Algorithms

Several independent search structures live beside Aho-Corasick because they solve different matching/indexing problems.

## KMP

`kmp.hpp` implements Knuth-Morris-Pratt style single-pattern searching. The testcase and YAML test vector cover direct matching behavior.

## Trie

`trie.hpp` provides prefix-oriented storage and lookup. The testcase covers insertion/lookup, scanning and auto-completion behavior.

## Suffix tree / Ukkonen

`suffixtree.hpp` and `ukkonen.hpp` provide suffix-tree-oriented indexing, with Ukkonen's construction used to build the suffix structure incrementally. Their tests exercise construction and lookup examples.

These implementations are separate from Aho-Corasick: Aho-Corasick is primarily a multi-pattern automaton, while these structures address single-pattern search or indexed substring/prefix problems.

## Tests

- `testcase_kmp.cpp`
- `testcase_trie.cpp`
- `testcase_suffixtree.cpp`
- `testcase_ukkonen.cpp`
- `testvector_kmp.cpp`
- `testvector_kmp.yml`
