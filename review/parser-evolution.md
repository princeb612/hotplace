# Hotplace Parser Evolution

> **Review baseline:** Revision 1096

Hotplace's parser is best understood as an evolution.

```text
lexer / CFG / LALR(1)
        ↓
context-dependent parser experiments
        ↓
Aho-Corasick related switching/reduction ideas
        ↓
GLR
        ↓
large parsing/action tables
        ↓
external binary parsing tables
        ↓
.ptb resources
```

The move toward GLR and the growth of the action table eventually made generated parser data a build concern. External `.ptb` resources separate that generated data from the source/build itself.

```text
test/tool/makeparsingtable
          ↓
binary_parsing_table::learn()
          ↓
        .ptb
          ↓
etc/parsingtable/parsingtable.zip
          ↓
CMake configure/generate
```

For ASN.1, `asn1notation.ptb` and `asn1.ptb` have different purposes and should not be treated as interchangeable.

Revision 1096 is the review boundary for production/rule naming; earlier parser experiments remain historical stages.

### Related source / documents

- `sdk/io/parser/`
- `test/tool/makeparsingtable`
- `etc/parsingtable/`
- `sdk/io/asn.1/`
- `sdk/io/parser/parser-generation.md`
- `sdk/io/parser/parsing-table-binary-format.md`

---

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1096                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
