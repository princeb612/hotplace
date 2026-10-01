# ASN.1 Node

## Role

`asn1_node` is the lightweight structural tree used to represent parsed ASN.1 TLV structure independently of the richer semantic type model.

It is intentionally simpler than `asn1_object`.

## Structural model

The node stores:

- identifier/P-C information
- tag
- encoded length
- name
- parent
- child list

There are two concrete structural forms:

- `asn1_primitive_node`
- `asn1_constructed_node`

The basic tree is therefore:

```text
asn1_node
   |
   +-- primitive node
   |
   +-- constructed node
          |
          +-- child
          +-- child
          +-- ...
```

## Why it is separate from `asn1_object`

The structural node describes what was encountered in an encoded ASN.1 stream.

The semantic object describes what the ASN.1 type means.

```text
DER / TLV
   |
   v
asn1_node
   |
   | structural representation
   v
semantic construction
   |
   v
asn1_object
```

Keeping these representations separate allows a decoded TLV tree to exist before schema-specific interpretation is applied.

## Operations

`asn1_node` supports:

- parent assignment
- child insertion
- iteration with `for_each`
- child count
- cloning
- reference counting
- clearing the child tree

The node therefore acts as a generic tree container rather than a full ASN.1 schema object.

## Related source

- `sdk/io/asn.1/basic/structural/asn1_node.hpp`
- `sdk/io/asn.1/basic/structural/asn1_node.cpp`
- `sdk/io/asn.1/basic/structural/asn1_primitive_node.*`
- `sdk/io/asn.1/basic/structural/asn1_constructed_node.*`

## Related documents

- `structural/structural.md` — earlier structural design notes
- `../asn1-object-model.md` — semantic representation

## Related tests

Structural parsing is exercised as part of the ASN.1 parser/DER testcase set under:

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`
