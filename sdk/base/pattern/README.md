### Pattern matching and string search

This directory contains pattern-matching and string-search implementations used by the SDK.

The source includes:
- Aho-Corasick matching, wildcard handling and the Aho-Corasick reducer.
- KMP, trie, suffix-tree and Ukkonen-style structures.
- Wildcard and regular-expression support.

The Aho-Corasick reducer is used where parsed/tokenized text needs to be reduced into higher-level matches. The implementations are reusable base facilities rather than protocol-specific parsers.
