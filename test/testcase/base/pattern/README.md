## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Pattern testcase directory

## 1. What

This directory tests distinct matching and indexing contracts implemented under [`sdk/base/pattern`](../../../../sdk/base/pattern/README.md): KMP substring search, trie lookup and prefix operations, Aho-Corasick multi-pattern matching, wildcard-aware matching, regex vectors, suffix-trie lookup, and Ukkonen suffix-tree queries.

The result shapes differ by algorithm. KMP returns a match position; trie tests include membership, prefix and indexed lookup; Aho-Corasick returns a multimap of inclusive source ranges and pattern IDs; suffix structures return sets of occurrence offsets. The test descriptions below retain those differences rather than treating every case as a generic “pattern found” check.

## 2. How

### 2.1 KMP: one known match across data representations

In [`testcase_kmp.cpp`](testcase_kmp.cpp), the source is `abacaabaccabacabaabb` and the pattern is `abacab`. The expected first-match index is hexadecimal `0xa`. The test searches four representations:

1. `binary_t` as a byte container;
2. contiguous memory via `data.data(), data.size()`;
3. a vector of `pattern_search_sample_data` values whose equality operator compares the `value` member;
4. a vector of pointers to those objects, using a comparator that compares pointed-to values.

Every path asserts that the returned index is `0xa`. This cross-representation check does not establish no-match behavior, overlapping-match behavior, or coverage of every comparator/element type.

### 2.2 Wildcard-aware Aho-Corasick: direct examples with expected ranges

In [`testcase_aho_corasick_wildcard.cpp`](testcase_aho_corasick_wildcard.cpp), the source sentence is:

```text
We don't playing because we grow old; we grow old because we stop playing.
```

The case inserts `we * old`, `stop *ing`, `*ing`, and `because *`, then compares the complete result multimap with expected inclusive ranges and pattern IDs. Expected matches include `we * old` at `25..35` and `38..48`, `stop *ing` at `61..72`, and `because *` at `17..73` and `50..73`. The second direct case uses `memberof_tolower_handler` and patterns `we *ing` and `we * old`; it checks `we *ing` at `0..15` and `58..72`, and `we * old` at `25..35` and `38..48`.

These two direct examples compare the complete result collections, not just the printed match text. The source comments explicitly say additional cases live in [`testvector_ahocorasick.yml`](testvector_ahocorasick.yml).

### 2.3 Trie: membership, prefixes, erase, lookup, and decode

[`testcase_trie.cpp`](testcase_trie.cpp) inserts `geek`, `geeks`, `code`, `coder`, and `coding`. Exact search expects those five strings to be present and `codex` absent; prefix checks expect `ge` and `cod` to match and `coz` not to match. It erases `geek` and `coding`, then asserts both are absent. The dump callback is followed by `assert(true)`, so the dump itself is not checked against a golden listing.

The autocomplete case inserts `hello`, `dog`, `hell`, `cat`, `a`, `hel`, `help`, `helps`, and `helping`, then calls `suggest("hel", 3, handler)`. Its assertion only checks that `suggest()` returned true; it does not compare the callback's suggested-word list with an expected list.

The lookup case inserts `hello` at index 0 and `world` at index 1. For source `helloworld`, lookup from offsets 0 and 5 must return length 5, while offset 1 returns 0. `find()` must map `hello` to 0 and `world` to 1, and return -1 for `word`. Reverse lookup checks index 0/1 against `hello`/`world`; index 2 must fail and leave the result empty.

The scan case inserts a Huffman code table into a trie and decodes a fixed bit string, including padding. The decoded sentence is compared with `We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw`; unlike dump/autocomplete, this is an expected-value assertion.

### 2.4 Aho-Corasick: overlapping matches, pattern IDs, and reducer rules

[`testcase_aho_corasick.cpp`](testcase_aho_corasick.cpp) inserts `he`, `she`, `hers`, and `his`, builds the automaton, and searches `ahishers`. The expected multimap contains four inclusive ranges and pattern IDs: `his` at `1..3` (ID 3), `she` at `3..5` (ID 1), `he` at `4..5` (ID 0), and `hers` at `4..7` (ID 2). Comparing the full multimap checks both overlap handling and the association between each range and its inserted pattern.

A second direct test uses a table with the same one example. Its comment says other cases were moved to the YAML vector file; it should not be described as a larger in-source table.

#### 2.4.1 What the YAML option combinations mean

[`testvector_ahocorasick.cpp`](testvector_ahocorasick.cpp) reads every item from [`testvector_ahocorasick.yml`](testvector_ahocorasick.yml), constructs the matcher based on `option`, inserts each key in `pattern`, builds the automaton, searches `input`, and compares the complete expected and actual multimaps. For each pattern key, the listed ranges are expected inclusive `[begin, end]` positions. Pattern IDs follow the order in which the YAML map entries are iterated and inserted, so a case is checked as a whole collection of `(range, pattern ID)` pairs.

The options are not just labels; they choose different matcher implementations:

| YAML option | Matcher selected by the consumer | Meaning demonstrated by the vectors |
|---|---|---|
| `[]` | `t_aho_corasick<char>` | Literal multi-pattern search. For example, `abcaabc` expects `abc` at `[0,2]` and `[4,6]`, and `a` at `[0,0]`, `[3,3]`, and `[4,4]`. |
| `[wildcards]` | `t_aho_corasick_wildcard<char>('?', '*')` | `?` matches one character and `*` matches a variable-length span. In `banana`, `??` matches `[0,1]` through `[4,5]`; `???` matches `[0,2]` through `[3,5]`; `b*a` has matches ending at indices 1, 3, and 5. |
| `[wildcards, ignorecase]` | Wildcard matcher with `memberof_tolower_handler` | Wildcard matching plus case-insensitive character comparison. For the sentence beginning with uppercase `We`, the pattern `we` additionally matches `[0,1]`, and `we *ing` matches `[0,15]` and `[58,72]`. |

The YAML has a progression from short, easy-to-check strings to mixed patterns and longer sentences. Items 4–8 isolate `?` and `*` with `banana`; items 9–12 exercise overlapping wildcard patterns against `ahishers`; items 13–17 use spaces, punctuation, and longer text; items 18–20 combine several patterns on the repeated sentence; items 21–25 add `ignorecase` and then exercise more complex `**` patterns and leading/trailing wildcard behavior. The comments on items 24 and 25 call out `**` and the startswith/endswith-any-wildcard cases, so these cases are intended to document more than the ordinary single-`*` examples.

**Implementation constraint:** the current builder handles `option: []`, `[wildcards]`, and `[wildcards, ignorecase]`. The code does not construct a matcher for `[ignorecase]` by itself. Keep the YAML options within those supported combinations unless the builder is deliberately extended.

#### 2.4.2 Reduction, token grouping, and repeat rules

The third direct test uses `t_aho_corasick_reducer<uint32>` to find structural patterns in token streams rather than characters in ordinary text. The example domain is ASN.1 notation: the test supplies token IDs for type declarations and compares the reducer's full result multimap against explicit expected ranges and rule IDs.

It first defines **token groups** with `group_as`: `token_builtintype` groups primitive types such as BOOLEAN, INTEGER, NULL, OBJECT IDENTIFIER, REAL, UTF8String, and VisibleString; `token_class` groups APPLICATION, PRIVATE, and UNIVERSAL; `token_taggedmode` groups IMPLICIT and EXPLICIT. A pattern can therefore match a category token rather than separately enumerating every member token.

It then registers reusable **sub-patterns**. For example, a tag is recognized as `[ number ]`, `[ class number ]`, `[ number ] IMPLICIT|EXPLICIT`, or `[ class number ] IMPLICIT|EXPLICIT`. Other sub-patterns represent `DEFAULT {}`, a tagged type, a named type, an enumeration element, and `SEQUENCE OF` / `SET OF` forms. Larger rules reuse those IDs: a named type may contain a built-in type, tagged type, user-defined type, enumeration body, or a defaulted sequence/set-of body.

Finally, **repeat rules** use `repeat_as` to recognize comma-separated repetitions without writing a separate fixed-length pattern for each list size. For example, `repeat_as(token_element, token_comma, {token_namedtype, token_taggedtype})` models a sequence of named/tagged elements separated by commas; another repeat rule groups named-number elements such as `homeOffice(0), fieldOffice(1), roving(2)`.

The five input examples make the intended reduction behavior concrete:

- `Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}` expects the outer sequence body at token range `2..9` (rule ID 14), plus named-type matches at `4..5` and `7..8` (rule ID 9).
- `Person2 ::= SEQUENCE {name [0] IMPLICIT VisibleString}` expects the outer body at `2..10`, a named/tagged type at `4..9`, and nested tag-related matches at `5..7`, `5..8`, and `5..9`.
- `Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}` expects the whole integer named-number body at `2..18` and three element matches at `4..7`, `9..12`, and `14..17`.
- `Person ::= SEQUENCE {name VisibleString, color ENUMERATED {red(0), green(1), blue(2)}}` checks the outer sequence, both field declarations, the enumeration body, and each named-number element.
- The longer `PersonnelRecord` example combines APPLICATION tags, IMPLICIT types, nested SEQUENCE/SET bodies, defaulted children, and repeated declarations; its expected multimap contains many nested and overlapping ranges. This is the broadest composition case in the source.

For each input, `lambda_test` compares `ac.search(input)` with the complete expected multimap. The frequency table is only logged afterward as “statistics for rule optimization”; those counts are diagnostic and are not themselves compared with expected frequencies. These cases show the particular grammar-like patterns registered in this test, not a general ASN.1 parser or exhaustive grammar coverage.

### 2.5 Standalone wildcard matching

[`testcase_wildcard.cpp`](testcase_wildcard.cpp) tests both character strings and token/pointer sequences. For text `baaabab`, wildcard symbols `?` and `*` are configured. `*****ba*****ab`, `ba?aba?`, and `ba?a*b` must match; `ba?ab?c` must not.

The pointer-based case represents a small token stream corresponding to declarations such as `bool a;` and `int b = 0;`. A custom accessor reads each pointed-to node's token. Positive expectations include `bool ?;`, `bool ?; *`, `? ? ? int ? = ?;`, and `* int ? = *;`; negative expectations include `* int ? = ;` and `* real *`. Each table row compares the matcher result with an explicit boolean expectation. This generic wildcard matcher is separate from wildcard patterns inside Aho-Corasick.

### 2.6 Suffix trie: exact occurrence-index sets

[`testcase_suffixtree.cpp`](testcase_suffixtree.cpp) searches a suffix-trie representation with fixed patterns and compares complete sets of occurrence indices. Cases include `ee` at `{1,9}`, `geek` at `{0,8}`, absent `quiz` at the empty set, and `forgeeks` at `{5}`. A second source string changes the expected offsets: `ee` at `{6,14}`, `geek` at `{5,13}`, and `forgeeks` at `{10}`; it also checks `est g` at `{1}`.

### 2.7 Ukkonen suffix tree: repeated and absent substrings

[`testcase_ukkonen.cpp`](testcase_ukkonen.cpp) builds trees for strings including `bananas`, `xabac`, `abcabcde`, and `THIS IS A TEST TEXT$` (the source includes the terminal $ sentinel). It checks sets of match offsets: `ana` in `bananas` is expected at `{1,3}`, `nana` at `{2}`, absent `apple` at the empty set, and `TEST` in the final text at `{10}`; the same case also expects `IS A` at `{5}` and `EXT$` at `{16}`. Another test adds `b`, `an`, and `anas` as suffix-tree components and expects searching `ana` to return `{1,3}`. Dump/debug output is diagnostic; the occurrence-set comparisons are the assertions.

### 2.8 Vector-driven KMP, Aho-Corasick, and regex cases

The `testvector_*.cpp` consumers load selected KMP, Aho-Corasick, and regex vectors from YAML. For Aho-Corasick, each YAML item constructs a matcher from its option list and compares expected inclusive ranges/pattern IDs with the actual search results. The detailed option meanings and reduction test are described in section 2.4. The regex path can depend on the compiler-selected backend, so a group-level result does not prove that every backend or platform exercised identical edge cases.

## 3. Evidence

### Source-level coverage

**1. KMP**

```text
same source/pattern -> byte storage / raw memory / value / pointer overloads
  -> search -> compare returned match index == expected index
```

**2. Wildcard Aho-Corasick and reducer**

```text
patterns + input + options -> match/reduce
  -> compare complete match-range / pattern-ID map (selected cases)
YAML vector -> consumer loads fields -> reducer -> compare expected/actual maps
```

Only the fields consumed and compared by the source are covered.

**3. Trie**

```text
insert words -> membership / prefix / indexed lookup -> compare selected results
erase word -> query membership -> compare erase effect
autocomplete -> check operation boolean; full suggestion list is not compared
dump -> diagnostic only
```

**4. Suffix structures and regex**

```text
selected text/pattern -> suffix or regex search -> compare selected offsets/match outcomes
```

These examples do not establish exhaustive overlapping-match, substring, regex or malformed-pattern coverage.



The supplied [Test Report Snapshot](../../test-report-status.md) records KMP, trie, Aho-Corasick, suffix-trie, Ukkonen, regex, and wildcard groups. These are group-level outcomes; they do not establish exhaustive algorithm coverage or make output-only cases equivalent to explicit expected-result checks. The report does not independently identify the tested source revision, OS, compiler, or complete build configuration.



## 4. Relationships

- [`sdk/base/pattern/README.md`](../../../../sdk/base/pattern/README.md) — implementation directory overview.
- [`testcase_kmp.cpp`](testcase_kmp.cpp) — exact first-match checks across four data representations.
- [`testcase_aho_corasick.cpp`](testcase_aho_corasick.cpp) — direct overlapping matches and token-level reduction/group/repeat rules.
- [`testcase_aho_corasick_wildcard.cpp`](testcase_aho_corasick_wildcard.cpp) — direct wildcard matching with explicit range/ID expectations.
- [`testvector_ahocorasick.cpp`](testvector_ahocorasick.cpp) and [`testvector_ahocorasick.yml`](testvector_ahocorasick.yml) — option-driven matcher selection and data cases.
- [`testcase_trie.cpp`](testcase_trie.cpp), [`testcase_wildcard.cpp`](testcase_wildcard.cpp), [`testcase_suffixtree.cpp`](testcase_suffixtree.cpp), and [`testcase_ukkonen.cpp`](testcase_ukkonen.cpp) — other direct test families.
- [`testvector_kmp.cpp`](testvector_kmp.cpp), [`testvector_kmp.yml`](testvector_kmp.yml), [`testvector_regex.cpp`](testvector_regex.cpp), and [`testvector_regex.yml`](testvector_regex.yml) — other vector consumers and data.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation limits.

## 5. References

No external reference is required to explain these testcase flows.
