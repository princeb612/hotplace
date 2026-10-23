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

# Aho-Corasick, wildcard extension and reduction

## 1. Role

hotplace has three related but distinct matching paths built around the Aho-Corasick trie:

1. **Base Aho-Corasick** finds occurrences of many literal patterns in one source scan.
2. **Aho-Corasick + wildcard** extends transitions to interpret single-element and zero-or-more wildcard symbols while searching multiple patterns.
3. **Aho-Corasick + reduction** treats the input as a token stream and recognizes groups, composite sub-patterns, repetitions and delimited blocks that can be represented as higher-level virtual tokens.

The first returns literal pattern occurrences. The second adds alternative matching paths for wildcard syntax. The third interprets matches as rules for transforming token-level spans. They share the automaton foundation, but they are not interchangeable modes of one simple search call.

## 2. Data Model

### Base automaton

Each `trienode` stores:

- `children`: exact-symbol transitions in the trie.
- `failure`: fallback state used when a transition cannot consume the next symbol.
- `output`: pattern IDs ending at the node, including IDs inherited from its failure state.
- `group_children` and `flag`: extension points used by grouped/reduced and wildcard paths.
- `last_visited`: generation marker used by the wildcard search to avoid processing a node repeatedly during one source step.

The automaton stores normalized pattern sequences in `_patterns`, keyed by pattern ID. Results are represented as `multimap<range_t, size_t>`: an inclusive source range paired with a pattern ID. Overlapping matches and multiple pattern IDs for a range can coexist.

### Wildcard extension

`t_aho_corasick_wildcard` adds wildcard symbols and marks wildcard-capable nodes with `flag_single` and `flag_any`. Its `_hidden` map retains prefix-pattern metadata needed to recover the correct beginning of matches involving `*`. This matters because the matched literal prefix alone does not identify the complete source range consumed by a wildcard expression.

### Reduction extension

The reducer adds token-oriented state on top of the automaton:

- `_token_to_groups` and `_group_ids` represent membership in virtual token groups.
- `_pattern_info_map` records metadata for sub-patterns and their virtual-token identity.
- `_repeat_rules` describes repeated token/rule sequences.
- `_treat_rules` describes a start-pattern/end-pattern block that can be treated as one result.
- Token-span mappings preserve correspondence between the transformed token stream and the original source ranges.

This extra state is rule metadata for token matching and reduction; it is not part of the base literal-pattern automaton.

## 3. Behavior Model

### Control-flow overview

```text
Base automaton
  insert patterns ─► build failure/output links ─► scan with one active state
                                                  └─ emit every output ID

Wildcard extension
  insert wildcard markers ─► build inherited links ─► scan active-state queue
                                                    └─ resolve original ranges

Reduction extension
  token stream + rules ─► match candidates ─► map to original spans
                                           └─ collapse virtual token / block / repeat
                                                └─ restart on shorter working stream
```

The three paths share trie/failure-link machinery, but their per-input-step state differs: the base automaton follows one state, wildcard matching explores a set of viable states, and reduction repeatedly transforms a token stream while preserving coordinates into the original input.


### A. Base Aho-Corasick

**`insert()` / `doinsert()`**

Adds each non-empty pattern to the trie. The terminal node records the pattern ID in `output`, and `_patterns` retains the sequence so the matcher can later calculate the match range.

**`build()` / `dobuild()`**

Builds failure links breadth-first. Root children fail to the root. For deeper transitions, the builder follows the parent's failure chain until it finds a state with the same outgoing symbol, or reaches the root. The destination then inherits the output IDs of its failure state. This output inheritance is what lets a match such as a shorter suffix-pattern be reported when a longer trie path also matches.

**`search()` / `dosearch()`**

Scans the source from left to right. On a missing transition, it follows failure links rather than restarting at the next source position. Every output ID at the active node is recorded against the current ending position; result conversion uses the stored pattern length to derive the inclusive start/end range.

**`order_by_pattern()`**

Reindexes an existing result collection by pattern ID, useful when the caller wants all occurrences of one pattern together rather than results grouped by source range.

**`set_greedy_filter()` / `greedy_filter()`**

Optionally removes overlapping matches. Candidates are ordered by start position and then by longer range first; a candidate covered by the last selected range is skipped. This is a selection policy applied to results, not a requirement of the Aho-Corasick algorithm itself.

### B. Aho-Corasick + wildcard

The wildcard extension has to do more than add `?` and `*` to the base trie. A literal automaton normally follows one exact transition and uses a failure link when it cannot continue. A wildcard node can instead create **multiple active paths**: a single-element wildcard consumes one source element, while the zero-or-more wildcard can match a variable-length span.

**`doinsert()`**

Inserts a pattern while marking wildcard nodes. Consecutive `*` symbols are normalized so that equivalent runs do not create redundant wildcard transitions. For patterns containing `*`, the implementation also stores hidden prefix metadata and flags for leading/trailing wildcard cases.

**`dosearch()`**

Uses a queue of active nodes rather than only one current state. At each source position it evaluates literal transitions and wildcard transitions, while failure links still provide fallback paths. The `last_visited` marker prevents the same node from being enqueued repeatedly in the same search step. This is the key structural difference from base Aho-Corasick: the matcher must track several viable states because wildcard paths can consume different spans.

**`get_result()`**

Converts matched internal pattern/prefix positions back into the original pattern IDs and source ranges. The hidden metadata is particularly important for `*`: it recovers the beginning of a match for a leading wildcard or for a pattern whose literal prefix is only a partial representation of the full expression.

The optional lowercase `memberof` handler makes character comparisons case-insensitive. It is an element-normalization choice, not a separate wildcard operator.

### C. Aho-Corasick + reduction

The reducer is interesting because it turns a set of pattern matches into a compact token vocabulary. A virtual token can stand for a concrete token group or a recognized sequence, allowing later parser stages to consume a higher-level unit instead of repeatedly handling the full lower-level sequence.

**`group_as()`**

Associates concrete token types with a virtual group. During search, a token can match its literal transition and transitions for groups containing that token. For example, INTEGER and VisibleString can both satisfy a `token_builtintype` transition without the caller having to register every concrete type combination separately.

**`insert_as()`**

Registers a token sequence as a pattern associated with a virtual-token identity. The reducer records pattern metadata separately from the raw sequence so the search result can be interpreted as a composite token match. In the ASN.1 example, `{token_identifier, token_builtintype}` can be recognized as `token_namedtype`, and `{token_sequence, token_lbrace, token_element, token_rbrace}` as a `token_sequencebody`.

**`repeat_as()`**

Registers a repeat rule with a virtual token, a set of target tokens and optionally a delimiter. The reduction pass first converts a target token into the virtual token. It then merges adjacent virtual/target elements, requiring the delimiter between them when one was configured. The merged token retains a span from the first element's original beginning to the last element's original end. The ASN.1 test uses this to reduce comma-separated named elements into `token_element`.

**`treat_as()`**

Registers a beginning pattern and an ending pattern for a block. At reduction time, the implementation scans for the beginning, then searches forward for the first matching ending pattern. It replaces the entire inclusive span with one virtual token and records a result covering the original span. This is a simple delimiter-based block collapse, not a nested-block parser: it does not maintain a stack or balance nested begin/end pairs.

**`dobuild()`**

Builds failure links for both ordinary and group transitions. Group links are built separately because a grouped token can follow a transition that a literal-only automaton would not consider equivalent.

**`dosearch()` / token search helpers**

Walk the token stream with literal and group-aware transitions, collecting candidate pattern IDs and positions. The reducer's path is therefore token-oriented; it does not simply treat arbitrary text characters as wildcard symbols.

**Reduction pass and span mapping**

`search()` first converts input items into a token-ID stream and initializes each token's original span to its own index. Each pass gathers Aho-Corasick matches and maps their ranges through the span table. If a virtual pattern matches, the longest virtual match is collapsed first, and the search restarts on the shorter stream. When no virtual pattern is selected, the pass evaluates `treat_as` and then `repeat_as`; a successful reduction restarts the pass. The final result set therefore retains both intermediate pattern matches and virtual matches, all expressed in original-input coordinates.

#### Trace: reducing an ASN.1 module header

The parser test configures these rules:

```cpp
ac.group_as(vtoken_symbol, {token_identifier, token_usertype});

ac.insert_as(vtoken_header_block_start,
             {vtoken_symbol, token_definitions});
ac.insert_as(vtoken_header_block_end,
             {token_assign, token_begin});

ac.treat_as(vtoken_header_clause,
            {vtoken_header_block_start},
            {vtoken_header_block_end});
```

For the input `EmployeeModule DEFINITIONS ::= BEGIN END`, the lexer produces five tokens:

| Original index | Token |
|---:|---|
| 0 | `EmployeeModule` (`token_identifier`) |
| 1 | `DEFINITIONS` |
| 2 | `::=` |
| 3 | `BEGIN` |
| 4 | `END` |

1. `group_as()` lets the identifier at index 0 satisfy the virtual `vtoken_symbol` transition.
2. `insert_as()` recognizes indices 0–1 as `vtoken_header_block_start`, and indices 2–3 as `vtoken_header_block_end`.
3. `treat_as()` finds that start token and the first end token after it, then collapses indices 0–3 into `vtoken_header_clause`.
4. The collapsed token keeps original span `[0, 3]`; the `END` token remains at original span `[4, 4]`. The search results and downstream test expectations still use these original coordinates even though the working stream is shorter.

The same test setup uses this technique for EXPORTS and IMPORTS clauses, with a semicolon as the end pattern. See `test/testcase/io/parser/asn1module.cpp` and the `aho corasick reduction (treat_as)` vectors in `test/testcase/io/parser/testvector_parser.yml`.

**Rule-mode constraint**

The source documents `repeat_as()` and `treat_as()` as mutually exclusive approaches. The implementation checks for applicable `treat_as` rules before attempting repeat rules and skips repeat processing for that pass when a block was collapsed; it does not reject a configuration merely because both rule collections are populated. Treat them as alternative reduction strategies rather than relying on a combined configuration.

The reducer can prepare token sequences for a parser, but it does not replace the grammar, parser state or semantic actions. It is a preprocessing layer that changes the granularity of the tokens presented downstream.

## 4. Relationships

- `aho_corasick.hpp/.cpp` — base literal-pattern automaton and match range handling.
- `aho_corasick_wildcard.hpp` — wildcard transition exploration and hidden prefix/range metadata.
- `aho_corasick_reducer.hpp` — token groups, composite patterns, repetitions and block reduction.
- `sdk/io/parser/` — parser/token-processing layer that can consume higher-level token matches.
- `test/testcase/base/pattern/testcase_aho_corasick.cpp` — base matches and reduction rules.
- `test/testcase/base/pattern/testcase_aho_corasick_wildcard.cpp` — wildcard and ignore-case paths.
- `test/testcase/io/parser/asn1module.cpp` and `test/testcase/io/parser/testvector_parser.yml` — concrete `treat_as` configuration and input/output span expectations.

## 5. References

- [Aho-Corasick algorithm for pattern searching in C++](https://www.javatpoint.com/aho-corasick-algorithm-for-pattern-searching-in-cpp)
- [Understanding failure links and output](https://daniel.lawrence.lu/blog/y2014m03d25/)

## 6. Development Notes (for maintainer review)
The implementation history records a source review of greedy filtering and a reset fix, followed by wildcard-search optimizations that normalize repeated `*` symbols and avoid repeated active-node work with generation-based visitation. These are meaningful implementation choices: the wildcard path has to control the number of active states, while reduction has to retain original token spans after replacing a sequence with a virtual token.

The reduction APIs were developed as an exploratory token-processing layer with Gemini assistance. The resulting design is worth understanding through its rule composition—`group_as`, `insert_as`, `repeat_as` and `treat_as`—rather than describing it as a generic pattern-search optimization.