## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
```

# QPACK Testcases

## 1. What

`test/testcase/net/qpack/` tests QPACK, the header-compression format used by HTTP/3. It covers RFC 9204 field sections and instruction streams, dynamic-table capacity and eviction, and captured encoder-stream/header-block inputs. It tests QPACK encoding/decoding and state transitions; it is not a live QUIC or HTTP/3 client/server suite.

| Source | Role |
|---|---|
| `testcase_capacity.cpp` | Zero/tiny capacity, bounded table state and eviction behavior |
| `testcase_rfc9204.cpp` | RFC 9204 examples, encoded-byte expectations, field decode and selected acknowledgements |
| `testcase_qpack_stream.cpp` | Captured encoder-stream and header-stream decoding |
| `test.cpp` | QPACK logging helper |

## 2. How

### 2.1 Capacity and eviction

1. Create a `qpack_encoder` and `qpack_dynamic_table`, and attach the debug hook that counts eviction events.
2. **Zero capacity:** insert the supplied field lines using the default zero capacity. Compare the selected encoded insertion with its fixed hex vector.
3. Still in the zero-capacity case, assert that capacity, entry count, table size, and eviction count remain zero.
4. **Capacity 32:** set the capacity to 32 and insert the supplied fields. Assert capacity, entry count, table size, and eviction count; the resulting bytes are dumped rather than compared with a fixed expected vector in this case.
5. **Capacity 80:** insert fields one by one. After each insertion, assert the expected single-entry table state, eviction count, and calculated table size.
6. Compare encoded bytes only for capacity-80 steps that supply an expected vector. The final insertion has no fixed expected-byte assertion. Eviction assertions use the debug hook's observed event count.

### 2.2 RFC 9204 examples

1. Run the selected RFC 9204 examples with their supplied field sections or encoder/decoder instruction inputs.
2. In the B.1 field-section path, encode the `:path` field, compare the encoded bytes with the RFC hexadecimal expectation, and check the field-section prefix values.
3. Decode the field section and compare the recovered field name and value with the expected values.
4. For the other examples, exercise the supplied encoder-stream capacity/insertion instructions, header sections, decoder instructions/acknowledgements, and selected dynamic-table state checks.
5. Evaluate each example against only the assertions it actually contains. The RFC test collection does not check every possible state property for every example.

### 2.3 Captured QPACK stream vectors

1. Select each captured stream sample together with its stream type and description.
2. Decode the sample bytes from Base16.
3. Call `qpack_encoder::decode` with the dynamic table and the corresponding encoder-stream or header-stream type.
4. Record the returned status through the testcase harness.
5. Do not interpret the description or packet-analysis comments as assertions. This callback does not compare a decoded field map or resulting table state with a separate expected object for every sample.

## 3. Evidence

### 3.1 Source-level coverage

#### Zero-capacity dynamic table

```text
default capacity (zero)
  -> insert field lines
  -> compare selected encoded bytes with fixed hex
  -> assert capacity == 0
  -> assert entries == 0
  -> assert table size == 0
  -> assert eviction count == 0
```

**Assertion strength:** one insertion's bytes plus four explicit state/eviction checks.

#### Tiny and bounded capacities

```text
capacity = 32
  -> insert fields
  -> assert capacity / entries / table size / eviction count
  -> dump encoded bytes (no fixed byte comparison)

capacity = 80
  -> insert field
  -> assert one table entry
  -> assert eviction count
  -> assert table size == name length + value length + 32
  -> compare encoded bytes only where an expected vector is supplied
  -> repeat for later insertions
```

**Assertion strength:** capacity-32 output is diagnostic. Capacity-80 checks table/eviction state on each insertion and compares bytes only for steps with a non-null expected vector.

#### RFC 9204 field sections and instruction streams

```text
RFC example input
  -> encode field section or encoder/decoder instruction
  -> compare selected encoded bytes with RFC hex
  -> decode/unpack selected instruction or field
  -> compare decoded name/value and prefix fields
  -> assert selected capacity / table size / acknowledgement bytes
```

**Assertion strength:** RFC paths combine fixed byte comparisons, decoded-field checks, and selected state/acknowledgement assertions. Not every RFC example checks all of these properties.

#### Captured stream samples

```text
captured stream bytes + stream type
  -> Base16 decode
  -> qpack_encoder::decode(dynamic table, stream type)
  -> test returned status
```

**Assertion strength:** status-only per-sample checks in this callback; no per-vector expected decoded map or expected table snapshot is compared.

### 3.2 Documentation and verification status

The latest available aggregate report for the parent `net` group is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole group. It does not separate QPACK results from other network tests or independently identify the tested source commit.

This documentation update did not execute tests. These sources do not establish QUIC transport behavior, packet protection, loss recovery, or end-to-end HTTP/3 interoperability.

## 4. Relationships

- [HTTP testcases](../http/README.md) — HTTP/2 frame/protocol path and related HTTP implementation.
- [HPACK testcases](../hpack/README.md) — HTTP/2 compression counterpart; QPACK has different synchronization behavior.
- [Network testcase group](../README.md) — shared entry point and aggregate report context.
- [Network SDK](../../../../sdk/net/README.md) — implementation area.

## 5. References

- RFC 9204 — QPACK: Field Compression for HTTP/3.
- `testcase_capacity.cpp`
- `testcase_rfc9204.cpp`
- `testcase_qpack_stream.cpp`
- [Test Report Snapshot](../../test-report-status.md)
