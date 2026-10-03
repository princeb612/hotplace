# Parsing Table Binary Format

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


The binary parsing table is the serialized execution artifact produced from the parser grammar-generation stage. It stores the string/terminal/production tables plus ACTION and GOTO entries needed by the parser engines.

The format documented here is the **Revision 1094 format**, still the source-tree baseline at Revision 1096. When the binary format changes, the format revision should be updated independently of the documentation publication revision.

## Generation and consumption

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

## File layout

> applied revision 1094

```
+-------------------------------------------------------+
| File Header (20 bytes)                                |
| - magic      :char[4] "HPT\0"                         |
| - version    :uint16  0                               |
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
