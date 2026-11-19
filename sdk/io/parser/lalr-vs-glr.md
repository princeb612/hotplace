> Source base : Revision 1132

### Developer Notes — LALR(1) vs GLR Parser Performance & Feature Comparison

#### 1. Core Performance Comparison

| Feature | LALR(1) Parser | GLR Parser |
| -- | -- | -- |
| Execution shape | One state stack and one selected action per state/lookahead | Multiple actions may be stored; execution maintains GSS heads and reduction paths |
| Time complexity | The LR algorithm is linear in token count for a fixed grammar; this implementation uses `std::map` table lookups, so lookup cost also depends on table size | Classical GLR literature often cites cubic worst-case time for general CFGs; this implementation has no measured or proven project-specific bound |
| Space complexity | One state stack, plus an optional parse tree | GSS nodes, parent edges and active heads depend on branching; no project-specific asymptotic bound or benchmark is established |
| Grammar support | Grammars for which the generated LALR table has no conflicts | The current generator stores multiple LALR-style actions and the engine attempts GSS paths; this is not a claim to support every CFG |
| Conflict handling | Conflicts cause table generation to return `conflict_detected` | Competing actions are retained in a multimap, but current shift-path deduplication can discard a distinct predecessor edge |
| Tree output | Optional `parse_tree` built from SHIFT/REDUCE events | The same single-stack `parse_tree`; it is not a shared packed parse forest |
| Current ASN.1 provider | Notation grammar revision 3 | Grammar revision 4; selected notation/parameterized testcase vectors use this path |

#### 2. Detailed Performance Analysis
① Time Complexity
- LALR(1)
  - The algorithm follows one action path and uses a single `std::stack<uint32>`; there is no runtime branching over competing actions.
  - The action and GOTO tables are `std::map` instances, so each lookup is logarithmic in table size rather than a literal constant-time array lookup. The usual linear-in-input-length description assumes a fixed grammar/table.
  - No current benchmark in this document establishes an implementation throughput or latency figure.
- GLR
  - The implementation stores multiple actions in a `std::multimap` and processes reductions over GSS paths before attempting shifts.
  - Classical GLR algorithms are often described with cubic worst-case time for general CFGs, but that theoretical bound must not be presented as a measured or guaranteed bound for this implementation.
  - The current shift phase deduplicates target states globally across active heads. If distinct heads select the same target state, later heads are skipped without adding another parent edge; therefore the implementation does not demonstrate complete preservation of all converging parse paths.
  - No benchmark in this document measures deterministic-section overhead or ambiguous-input performance.

② Space and Memory Complexity
- LALR(1)
  - Maintains one `std::stack<uint32>`; stack depth grows with the parse. An optional `parse_tree` adds its own nodes.
- GLR
  - Uses `std::shared_ptr` GSS nodes with parent vectors and an active-head vector. The current `t_gss::create_node()` always allocates a new node; it does not canonicalize nodes by state.
  - Reduction retracing and the `visited_reductions` set suppress repeated reduction work for a `(goto_state, ancestor)` pair. This is not equivalent to a general GSS node-merging algorithm.
  - The implementation's actual memory use depends on created nodes, parent edges and retraced paths; no measured cache-miss or memory comparison is available.

③ Expressiveness & Grammar Power
- LALR(1)
  - If a Shift/Reduce or Reduce/Reduce conflict occurs during table generation, `learn()` returns `conflict_detected` and the LALR table is not marked ready.
  - The grammar must be refactored or otherwise made conflict-free for this generator; no precedence-resolution layer is described by the current implementation.
- GLR
  - The current GLR generator reuses LR(0) states and LALR-style lookahead propagation, then stores competing actions in a multimap. It is not a canonical LR(1) construction and does not establish support for every context-free grammar. The simplified FIRST/FOLLOW and lookahead limitations are described in `parser-generation.md`.
  - The engine attempts multiple GSS reduction paths, but its same-target shift deduplication can omit predecessor links. Its optional `parse_tree` is a single node stack, not an ambiguity-preserving forest; do not claim that all valid parse trees are explored or resolved at a final disambiguation phase.
  - The project's ASN.1 GLR provider uses grammar revision 4 and selected parser test vectors; this demonstrates those tested syntax inputs, not complete ASN.1 conformance or C++ language parsing.
#### 3. Summary & Recommendation
- Choose LALR(1) when:
  - The grammar is conflict-free under the current LALR table generator.
  - A single deterministic parse path is sufficient, and predictable stack/table behavior is preferred.
- Choose GLR when:
  - The current grammar requires multiple actions at a state/lookahead and the relevant input cases have been validated against this implementation.
  - The consumer accepts the current GSS/parse-tree limitations and does not assume complete ambiguity preservation or general CFG support.
  - For the repository's ASN.1 grammar, the GLR provider is one tested parser path; syntax acceptance still does not establish semantic publication or full standards conformance.
