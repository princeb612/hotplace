## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parsing Table Binary Format

## 1. Role

`binary_parsing_table` is the persistence boundary between grammar-table generation and parser execution. It serializes symbol names, terminal IDs, productions, ACTION entries, and GOTO entries into a file that can be imported by a parser later. This avoids regenerating the table for every execution and makes grammar/table revision part of the runtime compatibility contract.

The file format is not the grammar itself and does not serialize lexical recognition rules or ASN.1 semantic objects. Those must still be supplied by the corresponding consumer.

## 2. Model

### Generation and consumption

```text
cfg_grammar
    │
    ▼
table generation
    │
    ▼
binary_parsing_table
    │
    ├── write → parsing-table binary file
    │
    └── read/import
          │
       ┌──┴──┐
       ▼     ▼
     LALR    GLR
```

### File layout

> ASN.1 grammar/table revision: 3 (source snapshot: Revision 1105)

```
+-------------------------------------------------------+
| File Header (20 bytes)                                |
| - magic      :char[4] "HPT\0"                         |
| - version    :uint16  grammar revision (ASN.1: 3)      |
| - endian     :uint16  0x1234                          |
| - crc32      :uint32                                  |
|  - crc32(BLOCK1 + BLOCK2 + .. + BLOCK5)               |
| - blocks size:uint64                                  |
|  - sum(BLOCK1 + BLOCK2 + .. + BLOCK5)                 |
+-------------------------------------------------------+
| BLOCK1 : String Table Block                           |
| - block length :uint64 (entries .. table)             |
| - table entries:uint32                                |
| - table                                               |
|   - len        :uint16                                |
|   - string     :char[len]                             |
|     - lexicographically ascending                     |
|     - indices 0, 1, 2, ... become the IDs.            |
|     - not null-terminated                             |
+-------------------------------------------------------+
| BLOCK2 : Terminal Index Block                         |
| - block length :uint64 (entries .. table)             |
| - table items  :uint32                                |
| - table                                               |
|   - terminals  :uint32[] -> string table              |
+-------------------------------------------------------+
| BLOCK3 : Production Block                             |
| - block length :uint64 (entries .. table)             |
| - table items  :uint32                                |
| - table                                               |
|   - rule id    :uint32                                |
|   - lhs id     :uint32   -> string table              |
|   - rhs count  :uint32                                |
|   - rhs ids    :uint32[] -> string table              |
+-------------------------------------------------------+
| BLOCK4 : Action Block                                 |
| - block length :uint64 (entries .. table)             |
| - table items  :uint32                                |
| - table                                               |
|   - state      :uint32                                |
|   - lookahead  :uint32   -> string table              |
|   - action     :uint8    -> parser_action_t           |
|   - target     :uint32                                |
+-------------------------------------------------------+
| BLOCK5 : Goto Block                                   |
| - block length :uint64 (entries .. table)             |
| - table items  :uint32                                |
| - table                                               |
|   - state      :uint32                                |
|   - nonterminal:uint32 -> string table                |
|   - next state :uint32                                |
+-------------------------------------------------------+
```

## 3. Important behavior and lifetime

- `write()` serializes five blocks, computes CRC32 over the concatenated block body, and prefixes the 20-byte header. The string table is based on the ordered `_string_index` map, so symbol IDs are assigned from that ordering rather than from arbitrary hash iteration.
- `read()` clears the table and the destination parser's grammar/state before loading. A failed import therefore should not be treated as leaving the previous parser ready for use.
- The reader checks the `HPT\0` magic, endian marker `0x1234`, total body size, and CRC32. It then reconstructs the string lookup maps, terminals, productions, ACTION entries, and GOTO entries.
- The header version is checked against `parser.get_cfg_grammar().get_revision()`: a table version lower than the receiving grammar revision returns `low_version`. This is a compatibility floor check, not a guarantee that every semantically incompatible table will be detected.
- Block lengths, counts, IDs, and symbol references are structural data. When changing the layout, update both read and write paths and preserve the header/version contract; do not update only the diagram in this document.

## 4. Example from the source tests

`test/testcase/io/parser/testcase_parser.cpp::test_load_parsingtable()` reads `asn1notation.ptb` into a `lalr1_parser` via `binary_parsing_table::read()`, checks the result, and then parses `Type1 ::= VisibleString`. In `test_asn1_notation()`, the ASN.1 advisor also supplies imported parser instances alongside runtime-built instances, giving a broader comparison of the generated and serialized paths.

To trace the bytes, start at `binary_parsing_table_write.cpp::write()` for BLOCK1–BLOCK5 and the header, then follow `binary_parsing_table_read.cpp::read()` in the reverse direction. The reader uses `payload` to read fixed-size fields and length-referenced symbol bytes, and rejects bad format, checksum mismatch, or an insufficient table version.

## 5. Relationships

- `parser-generation.md` — produces the logical table entries serialized here.
- `parser-engines.md` — consumes the reconstructed table during parsing.
- `../basic/` — payload and binary-stream primitives used for file encoding/decoding.
- `test/testcase/io/parser/testcase_parser.cpp` — exercises the imported-table path.

## 6. References

### Related source

- `binary_parsing_table.hpp`, `binary_parsing_table.cpp`
- `binary_parsing_table_write.cpp`, `binary_parsing_table_read.cpp`
- `test/testcase/io/parser/testcase_parser.cpp`
