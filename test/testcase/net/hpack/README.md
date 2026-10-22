## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
```

# HPACK Testcases

## 1. What

`test/testcase/net/hpack/` tests HPACK, the header-compression format used by HTTP/2. It covers RFC 7541 integer and header representations, Huffman coding, dynamic-table behavior, and YAML-driven header blocks. These tests exercise the compression layer; they are not a complete HTTP/2 client/server interoperability test.

| Source | Role |
|---|---|
| `testcase_huffman.cpp` | RFC 7541 Appendix B known-answer encode/decode vectors |
| `testcase_rfc7541.cpp` | RFC integer/header examples and selected dynamic-table state |
| `testvector_hpack.cpp` | YAML-driven compressed-header decoding and expected map comparison |
| `testvector_hpack.yml` | Named compressed blocks and expected header fields |
| `test.cpp` | Small HPACK logging helper |

## 2. How

### 2.1 Huffman known-answer vectors

1. For each sample in `testcase_huffman.cpp`, provide the input bytes and the fixed RFC hexadecimal encoding expected for that sample.
2. Call `do_test_huffman_codes_routine(sample, expect)` to encode the input.
3. Compare the encoded bytes with the fixed hexadecimal expectation.
4. Decode the encoded bytes and assert that decoding succeeds.
5. Compare the decoded bytes with the original sample bytes. This checks a known encoding and a round trip for the supplied samples.

### 2.2 RFC 7541 integer and header representations

1. Run the fixed integer-representation cases, including values such as 10, 1337, and 42, with their specified prefix widths and expected encodings.
2. Encode each integer and compare the produced bytes with the fixed hexadecimal expectation.
3. Decode the representation and compare the recovered integer with the original value.
4. Run header-representation cases using their configured indexing modes; compare encoded bytes with the expected vector and decoded header name/value with the expected fields.
5. For the cases that explicitly inspect the dynamic table, check the expected entry count and table size. The RFC request examples use separate encoder and decoder dynamic tables and decode sequences of header representations; the set of assertions varies by example, so not every case checks every table property.

### 2.3 HPACK YAML vectors

The authoritative HPACK YAML schema is defined here because this README documents the code that consumes it.

````yaml
testvector:
  - example: string                         # [mandatory] testcase
    schema: HPACK                           # [mandatory] "HPACK"
    items:
      - item: string                        # [mandatory] example label
        hpack: hexstring                    # [mandatory] encoded header block
        keyvalue:                           # expected decoded header map
          key: value
````

1. The vector consumer reads each `testvector` entry and its `items`; `item` labels the example, `hpack` contains the encoded header block, and `keyvalue` contains expected header name/value pairs.
2. Decode `hpack` from Base16 and convert `keyvalue` into the expected `std::multimap<std::string, std::string>`.
3. Decode the header representations using the `hpack_dynamic_table`. The same table is shared across the item loop, and decoded representations update its state as required.
4. Compare the decoded header multimap with the expected multimap.
5. Interpret the sequence as stateful: a prior item can affect dynamic-table state used by a later item. The callback does not independently compare the complete table with an expected snapshot for each item.

## 3. Evidence

### 3.1 Source-level coverage

#### Huffman known-answer and round trip

```text
sample bytes + expected RFC hex
  -> Huffman encode
  -> encoded bytes == expected bytes
  -> Huffman decode
  -> decode status == success
  -> decoded bytes == original sample bytes
  -> assertions
```

**Assertion strength:** both the fixed encoded bytes and the recovered input bytes are compared.

#### RFC 7541 integer representation

```text
integer + prefix width + expected hex
  -> encode_int
  -> decode_int
  -> decoded integer == original integer
  -> encoded bytes == expected hex
  -> assertion
```

**Assertion strength:** integer value and known-answer encoding are checked by the integer routine.

#### RFC 7541 header representations and dynamic table

```text
header name/value + indexing mode
  -> encode_header
  -> encoded bytes == expected hex
  -> decode_header
  -> decoded name/value == expected fields
  -> selected table entry-count / table-size assertions
```

**Assertion strength:** fixed byte comparisons and selected decoded-value/table-state checks. The exact set of table assertions varies across examples.

#### YAML header-block vectors

```text
testvector_hpack.yml
  -> schema "HPACK"
  -> item.hpack -> Base16 decode
  -> item.keyvalue -> expected multimap
  -> shared hpack_dynamic_table
  -> decode header representations until block consumed
  -> actual multimap == expected multimap
  -> testcase result
```

**Assertion strength:** exact equality of decoded header name/value maps. The dynamic table is used as decoder state, but this callback does not independently compare the whole table against an expected snapshot.

### 3.2 Documentation and verification status

The latest available aggregate report for the parent `net` group is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole group. It does not separate HPACK results from other network tests or independently identify the tested source commit.

This documentation update did not execute tests. The aggregate report is not an HPACK-only result and does not establish HTTP/2 interoperability.

## 4. Relationships

- [HTTP testcases](../http/README.md) — HTTP/2 frame and protocol-consumption paths.
- [QPACK testcases](../qpack/README.md) — related header compression for HTTP/3 with different state synchronization rules.
- [Network testcase group](../README.md) — shared entry point and aggregate report context.
- [Network SDK](../../../../sdk/net/README.md) — implementation area.

## 5. References

- RFC 7541 — HPACK: Header Compression for HTTP/2.
- `testcase_huffman.cpp`
- `testcase_rfc7541.cpp`
- `testvector_hpack.cpp` and `testvector_hpack.yml`
- [Test Report Snapshot](../../test-report-status.md)
