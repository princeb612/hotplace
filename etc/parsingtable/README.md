# parsing table (binary)

- ASN.1 notation only
  - suitable for LALR(1)
- ASN.1 notation, module definition, exports/imports, parameterized, information object class, extension marker (version 1 and 2)
  - suitable for GLR

references
- [file layout](../../sdk/io/parser/parsing-table-binary-format.md)

generation

- test/tool/makeparsingtable
```
  ./makeparsingtable -o asn1notation.ptb
  ./makeparsingtable -o asn1.ptb -glr
```

testcase
- unzip or copy before testing
```
  unzip parsingtable.zip -d test/testcase/io
  unzip parsingtable.zip -d test/testcase/asn.1
```

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```
