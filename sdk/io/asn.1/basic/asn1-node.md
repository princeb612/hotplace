## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Node

## 1. Role

`asn1_node` is the lightweight structural tree used to represent parsed ASN.1 TLV structure independently of the richer semantic type model.

It is intentionally simpler than `asn1_object`.

## 2. Data Model
### Structural model

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

### Why it is separate from `asn1_object`

The structural node describes what was encountered in an encoded ASN.1 stream.

The semantic object describes what the ASN.1 type means.

Keeping these representations separate allows a decoded TLV tree to exist before schema-specific interpretation is applied.

## 3. Behavior Model

### From decoded structure to semantic interpretation

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


### Build and traverse the structural tree

The structural node layer provides the generic operations needed to assemble and inspect a TLV tree: assign parent relationships, insert children, iterate descendants, count children, clone, clear, and manage shared lifetime.

```text
encoded ASN.1 TLV
       |
       v
asn1_primitive_node / asn1_constructed_node
       |
       +-- set parent / add child
       +-- traverse with for_each()
       +-- clone or clear
       |
       v
structural tree
       |
       v
schema-aware interpretation (separate step)
       |
       v
asn1_object model
```

A structural tree can exist before a schema has been selected or references resolved. It records tag/length and tree relationships; it does not by itself know the named ASN.1 type or all constraints implied by a schema.

### Related tests

Structural parsing and DER behavior are exercised across `test/testcase/asn.1/` and `test/testcase/asn.1/runtime/`. Those directories contain the relevant source-level test paths; this documentation update did not run them.

## 5. Relationships
### Related documents

- `structural/README.md` — distinction between the structural TLV tree and schema-driven semantic objects, including tagging examples
- `../asn1-object-model.md` — semantic representation

### Implementation source navigation
- `sdk/io/asn.1/basic/structural/asn1_node.hpp`
- `sdk/io/asn.1/basic/structural/asn1_node.cpp`
- `sdk/io/asn.1/basic/structural/asn1_primitive_node.*`
- `sdk/io/asn.1/basic/structural/asn1_constructed_node.*`
