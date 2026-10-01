# Pattern

`sdk/base/pattern` contains reusable string/pattern matching algorithms. The most project-specific part is the Aho-Corasick family, which has evolved from ordinary multi-pattern matching into token grouping/reduction used by parser work.

## Documents
- [Aho-Corasick](aho_corasick.md) — automaton, wildcard extension and reducer
- [Search algorithms](search-algorithms.md) — KMP, trie, suffix tree and Ukkonen structures
- [Wildcard and regex](wildcard-and-regex.md) — wildcard matching and regular expressions

## Related areas
- `sdk/io/parser/` — parser/token processing
- `sdk/io/string/` — URL parsing uses regex

## Related tests
- `test/testcase/base/pattern/`
