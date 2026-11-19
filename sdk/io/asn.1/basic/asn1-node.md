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
# ASN.1 Node

## 1. Role

`asn1_node` is the lightweight structural tree used to represent parsed ASN.1 TLV structure independently of the richer semantic type model.

It is intentionally simpler than `asn1_object`.

## 2. Data Model
### Structural model

The node stores:

- identifier/P-C information
- tag
- decoded content length (the TLV V length, not the complete TLV byte count)
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
DER / TLV bytes
   |
   v
asn1_bytestream
   |
   | t_tree<asn1_tlv_t> (identifier, tag, length, value offset)
   v
asn1_weakly_typed
   |
   | asn1_primitive_node / asn1_constructed_node
   v
asn1_node tree
   |
   | schema-less semantic promotion
   v
asn1_object
```


### Build and traverse the structural tree

The structural node layer provides the generic operations needed to assemble and inspect a TLV tree: assign parent relationships, insert children into containers, iterate immediate children, count direct children, clone, clear, and manage lifetime. `for_each()` is not recursive; callers must recurse themselves to visit descendants.

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

A structural tree can exist before a schema has been selected or references resolved. It records tag/length and tree relationships; it does not by itself know the named ASN.1 type or all constraints implied by a schema. A primitive node stores the value octets only, not the complete TLV header; a constructed node stores its child nodes. The primitive-node constructor copies value bytes only when the supplied span is in bounds; an invalid span leaves the value empty without returning an error. `add()` stores a child pointer and sets its parent without `addref()`; adding to a non-container primitive node releases the supplied child and silently does not insert it. The parent releases its children when cleared/destroyed. `addref()` / `release()` adjust the node's own shared counter; child references are released by `clear()` / destruction. Copy/clone is shallow: it copies child pointers and addrefs them rather than cloning descendants, and it copies the original parent pointer without rewriting the shared children's parent pointers. A clone is therefore not an independent deep tree.

### Related tests

The weakly typed DER path is exercised through `asn1_module::read_weakly_typed()` in `testcase_basic1.cpp`, `testvector_der.cpp` and `testvector_parser.cpp`: the runtime path is `asn1_bytestream` → `asn1_weakly_typed` → structural nodes → semantic objects. These tests exercise the surrounding decode/promotion path, but the current test tree has no direct assertions for `asn1_node::add()`, `for_each()`, `clone()` or parent-pointer behavior. The structural-node diagram in `testcase_basic2.cpp` is a source comment, not an executed node test. This documentation update did not run the tests.

## 4. Relationships
### Related documents

- `structural/README.md` — distinction between the structural TLV tree and schema-driven semantic objects, including tagging examples
- `../asn1-object-model.md` — semantic representation

### Implementation source navigation
- `sdk/io/asn.1/basic/structural/asn1_node.hpp`
- `sdk/io/asn.1/basic/structural/asn1_node.cpp`
- `sdk/io/asn.1/basic/structural/asn1_primitive_node.*`
- `sdk/io/asn.1/basic/structural/asn1_constructed_node.*`
