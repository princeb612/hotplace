## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1125                    │
│ Source basis: Revision 1125                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# OID Conversion

## 1. Role

`sdk/io/basic/oid.*` converts object-identifier notation between dotted decimal text and a vector of integer nodes. It also provides `asn1text_to_oid()` for extracting numeric nodes from the brace-and-label form used in ASN.1 descriptions. The adjacent `oid_dictionary` uses this representation for lookup.

```text
"2.16.840.1.101.3.4.2.1" ──str_to_oid──> [2,16,840,1,101,3,4,2,1]
ASN.1 braced notation ─────asn1text_to_oid─> node vector ──> oid_dictionary lookup
node vector ────────────────oid_to_str─────> dotted decimal text
```

## 2. Data Model

### Numeric representation: `oid_t`

`oid_t` is an alias for `std::vector<uint32>`. Each element is one numeric arc/node in the dotted representation. It is not a BER/DER byte sequence and does not retain the original text spelling, labels, or formatting.

The conversion API uses four data forms:

| Form | Role |
|---|---|
| Dotted decimal text, e.g. `2.16.840.1.101.3.4.2.1` | External textual input |
| `oid_t` node vector | Numeric intermediate representation used by the dictionary and ASN.1 layer |
| `asn1oid_t` (`std::vector<oid_elem>`) | Arc sequence that can retain a name alongside each numeric arc when parsing ASN.1-braced notation |\n| `basic_stream` | Output target for dotted decimal text or reconstructed ASN.1-braced notation |

### Token and cursor data

The dotted parser passes a character buffer, its size, a current scan position, and a delimiter boundary to the string-scanning helper. Each delimited decimal token is converted to `uint32` and inserted into the output vector.

The numeric ASN.1-style overload uses `regex_token()` to extract decimal runs into `oid_t`. The named overload uses `regex_tokens()` with a name/optional-number pattern and creates `oid_elem{arc, name}` entries in `asn1oid_t`. The named overload appends to the supplied vector rather than clearing it; callers that want replacement semantics must clear it first. These helpers extract notation components but do not constitute complete ASN.1 OID syntax or arc-constraint validation.

The adjacent dictionary stores metadata separately from the node sequence: `oid_metadata` contains a `name` and `description`, while `oid_dictionary` indexes node sequences in a trie. This allows the same OID value to be used independently of its human-readable label.

## 3. Behavior Model

### Dotted-decimal text to nodes

```text
str_to_oid(string)
       │ delegates to buffer + size overload
       ▼
clear output oid_t
       │
       ▼
scan for "." delimiters
       │
       ├─ each token span ─► t_atoi_n<uint32>()
       │                         │
       │                         ▼
       └──────────────────── append numeric node
                                 │
                                 ▼
                            oid_t vector
```

The implementation replaces the caller's previous output by clearing the vector before scanning. It converts the tokens it finds; this helper is not a complete semantic OID validator and does not independently enforce the ASN.1 first-arc/second-arc constraints.

### ASN.1-braced notation to nodes

```text
ASN.1-style text
       │
       ▼
regex_token(R"(\d+)")
       │
       ▼
list<range_t> decimal spans
       │
       ▼
convert each span to uint32
       │
       ▼
clear-and-fill oid_t
```

This is lexical extraction: labels such as `country(16)` contribute the digits `16`, while the surrounding labels and braces are not represented in `oid_t`. The caller must provide the expected notation and use the nodes in the appropriate ASN.1 context.

### Nodes to dotted-decimal text

```text
oid_t nodes
    │
    ▼
oid_to_str(nodes, basic_stream)
    ├─ clear destination stream
    ├─ write first node
    └─ for each remaining node: write "." then decimal node
                │
                ▼
          dotted text
```

The destination stream is cleared before output, so the function replaces previous stream contents rather than appending a second OID to them.

### Reverse conversion to ASN.1-braced notation\n\n`oid_dictionary::oid2asn1()` uses `t_trie::trace()` to walk the numeric arcs and collect the metadata name attached to each registered prefix. It emits `{name(number) ...}` for named arcs and a bare decimal arc when a traversed prefix has no metadata name. The current implementation requires every traversed prefix to be a registered terminal trie entry; a missing prefix or non-terminal prefix makes the conversion fail. This is a dictionary-backed reconstruction, not a lossless round trip of arbitrary original spelling.\n\n### Dictionary lookup is a separate step

```text
dotted text ──► str_to_oid() ──► oid_t ──┐
                                         ├─► oid_dictionary trie ──► oid_metadata
node vector ─────────────────────────────┘
```

The dictionary can also accept a node vector directly. A successful lookup copies the stored name and description into the caller's `oid_metadata`; an absent or empty node sequence does not produce a successful match. The dictionary lookup is not performed automatically by `str_to_oid()`.

### Failure and coverage boundaries

The conversion functions return `void`, so they do not provide a status code for malformed or out-of-range decimal tokens. A caller should not treat successful completion of the function as proof that the text is a valid ASN.1 OBJECT IDENTIFIER. The existing OID testcase demonstrates dictionary lookup from dotted text and ASN.1-braced text; it does not directly assert a conversion round trip through `oid_to_str()`.

### Concrete caller path: resolve an ASN.1-style OID label sequence

The OID testcase demonstrates the intended two-step operation: extract numeric arcs from ASN.1-braced notation, then ask the dictionary to resolve those arcs to metadata.

```cpp
#include <hotplace/sdk/io/basic/oid.hpp>

// From test/testcase/io/basic/testcase_oid.cpp
const char* text =
    "{joint-iso-itu-t(2) country(16) us(840) organization(1) "
    "gov(101) csor(3) nistAlgorithm(4) hashalgs(2) 3}";

oid_t oid;
asn1text_to_oid(text, strlen(text), oid);

oid_metadata meta;
auto dict = oid_dictionary::get_instance();
bool found = dict->lookup(oid, meta);\n\nbasic_stream notation;\nbool reconstructed = dict->oid2asn1(oid, notation);
```

The conversion produces only the numeric arc sequence; the dictionary lookup is a separate operation that supplies the human-readable name and description. The testcase asserts that lookup succeeds, but it does not establish that `asn1text_to_oid()` validates all ASN.1 OID notation rules.

Source: `test/testcase/io/basic/testcase_oid.cpp`.

## 4. Relationships
- `oid_dictionary.hpp/.cpp` — uses `str_to_oid()` to index and search the OID trie.
- `sdk/io/asn.1/basic/` — uses the conversion helpers as part of ASN.1 value encoding/decoding; BER/DER rules live there.
- `sdk/base/nostd/atoi.hpp` and `sdk/base/string/string.hpp` — numeric token conversion and scanning helpers used by this implementation.
- `sdk/base/stream/basic_stream.hpp` — output target for `oid_to_str()`.

### Implementation source navigation

- `sdk/io/basic/oid.hpp/.cpp`
- `sdk/io/basic/oid_dictionary.hpp/.cpp`

## 5. References
- [ITU-T X.660 / ISO/IEC 9834-1](https://www.itu.int/rec/T-REC-X.660/en) — object identifier framework.
- [ISO/IEC 6523-1](https://www.iso.org/standard/63547.html) — identification of organizations and organization parts.
