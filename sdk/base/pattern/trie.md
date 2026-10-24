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

# Trie

## 1. Role

`t_trie` stores sequences by shared prefixes. A node can represent a prefix without representing a complete key, so the structure supports exact lookup and prefix-oriented operations in the same index.

Two concrete hotplace consumers make this distinction useful:

- Huffman decoding walks a code stream and selects the longest code that matches at the current position.
- The OID dictionary indexes an object identifier as a sequence of numeric arcs and attaches name/description metadata to the terminal node.

## 2. Data Model

Each `trienode` contains:

- `children`: ordered map from normalized symbol `BT` to child node.
- `eow`: marks that the path is a complete stored key.
- `index`: integer identifier associated with that key.
- `value` and `parent`: symbol and parent link used to reconstruct a key.

The template parameters separate the comparison symbol (`BT`), input element (`T`), optional tag type (`TP`) and element extractor (`memberof_t`). Tags are additional caller data; they are not the key's integer index. The trie owns and deletes registered tag pointers.

## 3. Behavior Model

### Terminal-state invalidation

`invalidate()` clears terminal status and resets the index without necessarily deleting shared prefix nodes. This lets a key be removed while retaining nodes that may still be prefixes of other stored keys.

### Insert and exact lookup

**`insert()` / `add()`**

Walks the input sequence from the root. Missing child nodes are created as needed. The terminal node is marked with `eow`, assigned an index if needed, and optionally associated with a tag.

**`search()`**

Returns true only when the entire input path exists and its final node has `eow == true`. Finding a path that is merely a prefix of another key is not enough.

**`find()`**

Performs the same exact-key traversal but returns the stored integer index. Missing or non-terminal paths return `-1`.

### Prefix and longest-match operations

**`prefix()`**

Checks whether the path exists. The optional `eow` output indicates whether the last traversed node is itself a complete key.

**`lookup(input)`**

Returns the length of the longest stored key matching from the beginning of the input. The return value is a length, not a source end offset or key index.

**`scan(input, size, pos)`**

Starts at `pos` and continues while transitions exist. Each terminal node updates the best match, so a later, longer key wins over an earlier shorter key. On success, the method returns that key's index and advances `pos` to the end of the longest match. On failure, it sets `pos` to `size` to signal termination.

### Reverse lookup and maintenance

**`lookup(index, pattern)`**

Uses the reverse index to walk parent links from the terminal node to the root and reconstruct the stored key.

**`suggest()` / `dump()`**

Traverse descendants and invoke a caller-provided handler for stored keys. `suggest()` first follows the supplied prefix.

**`erase()`**

Invalidates the terminal key and deletes its tag. Shared nodes are retained when they may still form prefixes for other keys.

**`reset()` / `clear()`**

`reset()` rebuilds the root when it has children, then clears tag and reverse-index state. `clear()` clears auxiliary maps and deletes registered tags.

### Source flow: path existence is not key existence

```text
insert(key, index, tag)
  root ── symbol 0 ── child ── symbol 1 ── ... ── terminal
                                                   ├─ eow = true
                                                   ├─ index
                                                   └─ optional tag

search(key) / find(key)
  root ── follow every symbol ──► final node
                                  ├─ eow = true  ─► key exists / index
                                  └─ eow = false ─► only a prefix, not a key

scan(input, pos)
  follow transitions from pos; remember each terminal encountered
  └─ when traversal stops, return the last terminal (longest key)
```

That terminal marker is the semantic boundary between a stored key and an internal prefix. For example, after inserting `ab` and `abcd`, the node for `ab` is terminal even though it has descendants; a path such as `abc` may exist without being a stored key. `scan()` uses the last terminal visited rather than simply returning the deepest node reached.

## 5. Relationships

### Huffman coding: decode a prefix code

`sdk/base/encoding/huffman_coding.hpp` embeds a `t_trie<char>` as `_trie`. Each Huffman bit-string is inserted as a key, with its decoded symbol stored as the key index. During decoding, `scan()` consumes the longest code at the current bit position and returns the symbol. The position is advanced to the next code boundary, so decoding repeats until the bit stream is consumed.

This is a direct use of longest-prefix matching: the trie is not building the Huffman tree or calculating code lengths; it is indexing a code table that has already been learned or imported.

### OID dictionary: numeric arcs and metadata

`sdk/io/basic/oid_dictionary.hpp` uses `t_trie<uint32, uint32, oid_metadata>`. An OID is converted into a vector of numeric arcs; the arc values, rather than the dotted decimal text, form the trie path. The terminal node's tag points to `oid_metadata`, containing the name and description.

`oid_dictionary::insert()` converts or accepts the arc sequence and stores the metadata tag. `lookup()` uses exact `search()` and retrieves the tag. This is dictionary lookup, not longest-prefix matching of textual OID strings.

### Other relationships

- `pattern.hpp` — default/custom element extraction for values, objects and pointers.
- `aho_corasick.md` — shares trie-shaped prefix storage, but adds failure links to find multiple patterns throughout a source.
- `test/testcase/base/pattern/testcase_trie.cpp` — tests exact search, prefix checks, erase, suggestions, longest-prefix lookup, reverse lookup by index and Huffman-code scanning.

## 6. References

- [Trie data structure in C++](https://www.geeksforgeeks.org/trie-data-structure-in-cpp/)
- [Autocomplete using a Trie](https://www.geeksforgeeks.org/auto-complete-feature-using-trie/)
