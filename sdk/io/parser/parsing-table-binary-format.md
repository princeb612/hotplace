## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parsing Table Binary Format

## 1. Role

`binary_parsing_table` is the persistence boundary between grammar-table generation and parser execution. It serializes symbol names, terminal IDs, productions, ACTION entries, and GOTO entries into a file that can be imported by a parser later. The header carries the grammar revision; the reader compares it with a configured minimum revision when one is present. Current ASN.1 import accessors leave the receiving grammar revision at zero, so their import paths do not enforce a meaningful revision floor.

The file format is not the grammar itself and does not serialize lexical recognition rules or ASN.1 semantic objects. Those must still be supplied by the corresponding consumer.

## 2. Data Model

### Logical table and file representation

The logical table contains symbols, terminal registrations, productions, ACTION entries and GOTO entries. The .ptb file stores these as five blocks behind a fixed 20-byte header. IDs in the blocks refer to the serialized string table; they are not raw C++ pointers or stable IDs across arbitrary grammar revisions.

### File layout

> ASN.1 grammar/table (source snapshot: Revision 1104)

```
+-------------------------------------------------------+
| File Header (20 bytes)                                |
| - magic      :char[4] "HPT\0"                         |
| - version    :uint16  CFG grammar revision            |
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

### Intermediate data used by import/export

| Data | Role |
|---|---|
| Ordered string index | Assigns reproducible IDs to symbol spellings |
| Terminal ID sequence | Records serialized terminal symbols |
| Production records | Reconstruct LHS and ordered RHS symbol lists |
| ACTION records | Reconstruct action choice for state/lookahead |
| GOTO records | Reconstruct next-state transitions for non-terminals |
| Header version | Grammar revision written by the producer; compared with the receiving parser's configured minimum revision (default zero in current ASN.1 import accessors) |
| CRC32 and body size | Integrity and framing checks |

## 3. Behavior Model

### Write path

```text
binary_parsing_table::learn(parser)
          │
          ├─ collect grammar symbols / productions / terminals
          ├─ build ordered string table and symbol IDs
          └─ parser->build(this) copies ACTION / GOTO
                          │
                          ▼
binary_parsing_table::write(filename, parser)
          │
          ▼
serialize BLOCK1 through BLOCK5
          │
          ▼
compute CRC32 over concatenated block body
          │
          ▼
write 20-byte header + body size + CRC
          │
          ▼
.ptb artifact
```

### Read/import path

```text
binary_parsing_table::read(file, parser)
          │
          ▼
clear table + destination parser grammar/state
          │
          ▼
read and validate header
  ├─ magic == "HPT\0"
  ├─ endian marker == 0x1234
  ├─ body size matches
  └─ CRC32 matches
          │
          ▼
parse five blocks; payload checks field bounds against the whole file
          │
          ▼
reconstruct string index, terminals, productions,
ACTION and GOTO entries
          │
          ▼
compare table version with grammar revision
  ├─ older than required ─► low_version
  └─ accepted ────────────► usable parser table
```

Import clears the destination parser/table before reconstruction. A failed read should not be assumed to preserve a previously ready parser. The revision check is a compatibility floor, not proof that every semantically incompatible artifact is detected.

### Failure and maintenance boundary

The reader checks the fixed header, endian marker, total body size, CRC32, and the configured minimum table revision. It reads the five blocks in sequence, but the stored per-block length fields are parsed and then ignored; payload reads are bounded by the whole file, not by each block's declared length. The reader also does not validate every symbol ID/reference or action enum before rebuilding the parser: an unknown string-table ID can resolve to an empty string, and the serialized production ID is read but the grammar assigns production IDs again from insertion order. Trailing bytes after the five blocks are not explicitly rejected. Do not describe this as complete block/reference validation.

The writer builds its in-memory tables only after `binary_parsing_table::learn(parser)`; `write()` itself serializes the current vectors. The current `write()` implementation does not check the `ofstream` open/write result and returns its initially successful status even if the file output fails. When changing the format, update writer and reader together and review the version contract. The .ptb artifact does not carry lexer configuration, token-to-terminal mapping or semantic builder.

### Source-level evidence

test/testcase/io/parser/testcase_parser.cpp::test_load_parsingtable() imports asn1notation.ptb into a default-constructed lalr1_parser, records the read result, and then parses Type1 ::= VisibleString without guarding that parse call on the read status. test_asn1_notation() also compares runtime-built and imported parser readiness/parse status. These tests do not compare golden .ptb bytes, corrupt individual block lengths/IDs, or assert rejection of trailing bytes. Follow binary_parsing_table_write.cpp::write() and binary_parsing_table_read.cpp::read(); the reader uses payload for fixed-width and length-referenced fields.

## 4. Relationships
- `parser-generation.md` — produces the logical table entries serialized here.
- `parser-engines.md` — consumes the reconstructed table during parsing.
- `../basic/` — payload and binary-stream primitives used for file encoding/decoding.
- `test/testcase/io/parser/testcase_parser.cpp` — exercises the imported-table path.

### Implementation source navigation
- `binary_parsing_table.hpp`, `binary_parsing_table.cpp`
- `binary_parsing_table_write.cpp`, `binary_parsing_table_read.cpp`
- `test/testcase/io/parser/testcase_parser.cpp`
