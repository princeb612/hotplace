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

# Suffix trie and Ukkonen construction

## 1. Role

This page covers two related but structurally different substring indexes. `t_suffixtree` inserts every suffix explicitly into a trie. `t_ukkonen` constructs a compressed suffix tree using Ukkonen's online construction technique. Both return source positions for a matching substring, but they use different construction and storage strategies.

## 2. Data Model

### `t_suffixtree`: explicit suffix trie

Each node maps a symbol to a child and carries a set of source indices. The index set records which suffix starts pass through that node. The source sequence is retained in `_source`.

### `t_ukkonen`: compressed suffix tree

Each node stores child transitions, an edge interval `start..end` into `_source`, a leaf `suffix_index`, and a `suffix_link`. Construction state is held in `_active_node`, `_active_edge`, `_active_length` and `_remaining_suffix_count`. Edge labels refer to ranges in the source rather than copied strings.

## 3. Behavior Model

### Explicit suffix trie

**`add()`**

Appends normalized symbols to `_source`, then inserts a suffix starting at each source position. Every suffix is represented as a path, so the implementation is straightforward but can require quadratic space.

**`search()`**

Follows the query symbols from the root. If the path exists, returns the stored set of source indices associated with that node; otherwise returns an empty set.

**`reset()`**

Replaces the root and clears the source sequence.

### Ukkonen compressed suffix tree

**`add()`**

Resets the previous index, stores the normalized source, initializes the active point and remaining-suffix count, and calls `extend()` for each source position. After construction it assigns suffix indices to leaves.

**`extend(pos)`**

Adds the current source position to the online construction. Depending on the active point, it either creates a leaf, walks down a complete edge, extends an existing match, or splits an edge. New internal nodes are connected by suffix links so the next pending suffix can reuse prior work.

**`set_suffixindex()`**

Traverses the finished tree and assigns each leaf the starting index of the suffix represented by that leaf.

**`search()`**

Walks edge intervals while matching the query. Once the query is exhausted, collects suffix indices beneath the matched locus into a sorted set.

**`reset()`**

Deletes the old tree and initializes an empty root and construction state.

The key trade-off is explicit suffix paths versus compressed edge intervals. The former is easier to follow as a reference implementation; the latter is designed to avoid rebuilding every suffix path independently.

### Construction and query traces

```text
t_suffixtree::add(source)
  ├─ retain normalized source
  └─ for each suffix start i
       └─ insert source[i..end] as an explicit root-to-leaf path

t_ukkonen::add(source)
  ├─ reset old tree and initialize active point
  └─ for each source position pos: extend(pos)
       ├─ resolve active edge/length
       ├─ walk down a complete edge when possible
       ├─ create leaf or split edge on mismatch
       └─ link successive internal nodes through suffix links
            └─ after all extensions, assign leaf suffix_index values

search(query)
  ├─ explicit trie: follow one symbol transition at a time
  └─ Ukkonen: compare query against source intervals on edges
       └─ collect descendant leaf suffix indices and sort
```

The storage difference is visible in the edge labels: the explicit suffix trie materializes a path for each suffix, while Ukkonen nodes refer to intervals in the retained source. In the compressed tree, a query may finish partway through an edge; all leaves below that matched locus still identify occurrences of the query.

## 4. Relationships

- `pattern.hpp` — shared element extraction for source sequences.
- `test/testcase/base/pattern/testcase_suffixtree.cpp` — explicit suffix-trie queries.
- `test/testcase/base/pattern/testcase_ukkonen.cpp` — Ukkonen construction and substring queries.
- `README.md` — places both indexes among the other pattern-matching choices.

## 5. References

- [Pattern searching using Trie of all suffixes](https://www.geeksforgeeks.org/pattern-searching-using-trie-suffixes/)
- [Ukkonen's suffix-tree construction — Part 1](https://www.geeksforgeeks.org/ukkonens-suffix-tree-construction-part-1/)
- [Ukkonen algorithm animation](https://brenden.github.io/ukkonen-animation/)
- [Ukkonen's suffix-tree algorithm](https://programmerspatch.blogspot.com/2013/02/ukkonens-suffix-tree-algorithm.html)
