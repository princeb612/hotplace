### ASN.1 loader testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_loader.cpp`

The loader testcase verifies both the initial file-loading/parsing step and the later semantic publication step.

```text
ASN.1 file
   |
   v
loader.load_file()
   |
   v
parse_tree
   |
   v
asn1_publisher::build()
   |
   v
asn1_runtime
```

The current test also exercises the parser's explicit intermediate stages (`to_tokens()`, `to_parsetree()`, `to_result()`), regenerated module notation, `EXPORTS`/`IMPORTS`, and `is_resolvable()` across imported module definitions.

Detailed implementation notes belong to the corresponding `sdk/io/asn.1/` documentation.
