## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— QUIC packet construction, RFC vectors & capture replay
```

# QUIC Testcases

## 1. What

`test/testcase/quic/` contains executable QUIC testcase sources and a YAML-driven HTTP/3 capture-vector reader. The registered test flow covers QUIC variable-length integers and packet-number encoding/decoding (RFC 9000), QUIC v1 initial secrets and packet protection (RFC 9001), QUIC v2 examples (RFC 9369), a walkthrough based on QUIC Illustrated, and selected 1-RTT packet processing.

The group is not a live QUIC client/server interoperability suite. Most cases create `tls_session` objects, inject known protocol inputs, construct or parse packet bytes, and compare selected outputs with published expected values. The HTTP/3 vector path exercises QUIC packet/frame processing from an ordered fixture; it does not currently perform a full TLS 1.3 record replay or assert a complete HTTP/3 request/response transaction.

The `http3/` child directory retains a recorded `http3.pcapng`, associated `sslkeylog` material and explanatory client-side curl output. Those files are diagnostic evidence from a recorded experiment, not independent CTest targets. Their inventory notes are kept as Developer Notes.

## 2. How

### Test flow at a glance

```text
sample.cpp
    |
    +--> RFC 9000
    |      varint / packet-number expected values
    |
    +--> RFC 9001 / RFC 9369
    |      Initial secrets + packet vectors
    |      construct / protect / parse
    |
    +--> QUIC Illustrated / selected 1-RTT
    |      selected packet inputs + status checks
    |
    +--> PCAP SIMPLE HTTP/3 vector
           direction + packet bytes
                    |
                    v
              QUIC packet parser
                    |
              frame / alert handling
                    |
          assertions and testcase status

Stored PCAP + SSLKEYLOG + curl output = experiment artifacts,
not a live end-to-end QUIC interoperability test.
```

The RFC known-value checks and the walkthrough/status paths are not equivalent evidence. Read each case's assertions before treating a successful parse or printed packet label as a verified field value.

### 2.1 Test dispatch and build inputs

1. `sample.cpp` initializes the shared testcase harness, logger and OpenSSL support, then calls `testcase_understand_quic()`, `testcase_rfc_9000()`, `testcase_rfc_9001()`, `testcase_rfc_9369()`, `testcase_testvector_pcap()` and `testcase_construct_1rtt()`.
2. `testcase_construct_quic()` is present as a construction walkthrough but its call is commented out in the normal entry-point flow. Its source should not be counted as an executed testcase merely because it compiles into the target.
3. The directory's `CMakeLists.txt` collects top-level C++ sources into the `quic` test target and copies top-level `.yml` fixtures into the build tree's QUIC testcase directory.
4. The currently registered YAML vector is `testvector_pcap_http3.yml`. The HTTP/3 capture and key-log artifacts under `http3/` are separate study materials; CMake does not turn each artifact into its own test target.

### 2.2 QUIC Illustrated walkthrough

1. `testcase_understand_quic()` calls `test_quic_xargs_org()`, which follows selected steps from [QUIC Illustrated](https://quic.xargs.org/).
2. The testcase creates a QUIC session, supplies an X25519 key-share private key for the illustrated client-key-exchange step, and sets the destination connection ID used to derive Initial secrets.
3. It calculates the Initial protection material and explicitly compares selected client/server Initial keys, IVs and header-protection keys against fixed hexadecimal expectations.
4. It then feeds selected captured/constructed packet byte sequences into `quic_read_packet`, reporting the packet type and read status for the illustrated handshake and application-data exchange.
5. The packet-read calls provide parser/status coverage for these chosen examples. The exact expected-value assertions on the Initial secrets are stronger checks; diagnostic packet labels and a successful read status alone do not prove every decoded frame field or a live network exchange.

### 2.3 RFC 9000: variable-length integers and packet numbers

1. `testcase_rfc9000.cpp` decodes the RFC 9000 Appendix A.1 sample values and boundary examples spanning the 1-, 2-, 4- and 8-byte QUIC variable-length integer encodings.
2. Each decode case passes hexadecimal bytes to `quic_read_vle_int` and asserts the resulting integer equals the expected value. Additional examples encode the same value using different valid prefix/length forms and check the decoded result.
3. The write cases call `quic_write_vle_int` and compare the resulting bytes with the expected encoding, including explicit prefix selections for a small value.
4. Appendix A.2 cases call `encode_packet_number` and assert both the truncated representation and required bit count. Appendix A.3 calls `decode_packet_number` and compares the reconstructed packet number to the expected full value.
5. These are focused algorithm-level comparisons. They do not by themselves establish malformed-input handling or exhaustive coverage of all packet-number reconstruction windows.

### 2.4 RFC 9001: QUIC v1 Initial secrets and packet protection

1. `testcase_rfc9001.cpp` prepares client/server QUIC sessions using the RFC destination connection ID, then calculates Initial protection material.
2. The RFC 9001 Appendix A.1 case compares the Initial secret and selected client/server traffic secrets, keys, IVs and header-protection keys against published hexadecimal values.
3. The client Initial and subsequent packet cases populate a `testvector_initial_packet` with the direction, connection IDs, token/frame bytes, packet number and length, plus expected unprotected/protected headers and final packet bytes.
4. `test_rfc_9001_construct_initial` creates a `quic_packet_initial`, serializes the unprotected header, applies packet protection and checks the payload, final packet bytes, packet type, connection IDs, body size, packet number, packet-number length, and expected protected/unprotected headers.
5. The corresponding read path parses packet bytes and checks selected decoded fields/status. The Retry case uses its own vector structure and compares the constructed result and integrity tag with the expected values.
6. The Appendix A.5 minimal-packet example is currently explanatory commented material; it is not an active assertion. The RFC 9001 §4 routine is explicitly a study placeholder, so do not describe it as verifying the complete TLS-message-carrying procedure.

### 2.5 RFC 9369: QUIC v2 vectors

1. `testcase_rfc9369.cpp` repeats the selected Initial-secret and packet-protection checks for QUIC version 2 using RFC 9369 Appendix A vectors.
2. The key case compares the derived Initial secret, client/server Initial secrets, keys, IVs and header-protection keys against the published values.
3. The client/server Initial and Retry cases supply version-2 packet inputs and expected headers, packet bytes or integrity tags to the shared construction/read helpers.
4. The active assertions validate these specific vectors and derived values. The commented minimal-packet walkthrough is explanatory text rather than a runtime test.

### 2.6 Selected 1-RTT packet processing

1. `testcase_construct_1rtt.cpp` initializes a QUIC v1 session with the cipher suite and fixed application-level client header-protection key, packet key, IV and destination connection ID from the recorded ACK example.
2. It parses a fixed encrypted packet with `quic_packets::read`, then checks selected decoded packet properties.
3. It constructs a packet containing a known payload, serializes it, reads the generated bytes back, and asserts the decoded packet number.
4. These checks cover selected 1-RTT packet parsing and round-trip construction under preloaded secrets. They are not a complete key-update, stream-reliability or live transport test.

### 2.7 PCAP SIMPLE HTTP/3 vector

The QUIC reader consumes a reduced YAML vector representation, not a raw `.pcapng` file. The schema used by `testvector_pcap.cpp` is illustrated below; `string` and `hexstring` are explanatory placeholders.

```yaml
testvector:
  - example: string
    schema: PCAP SIMPLE
    protocol: "HTTP/3"
    secrets:
      - item: string
    items:
      - item: string
        dir: "from_client" | "from_server"
        protocol: "TLS 1.3" | "QUIC"
        frame: hexstring
```

1. `testcase_testvector_pcap()` calls `play_yaml_pcap_http3("testvector_pcap_http3.yml")`; the YAML runner dispatches the vector to the handler registered as `PCAP SIMPLE`.
2. The handler requires the vector-level `protocol` value to be `HTTP/3`. A different value causes an assertion and returns from that vector.
3. It creates one TLS session and one QUIC session for the replay call, clears the shared `sslkeylog_importer`, attaches it to both sessions, and imports each `secrets[].item` line when the sequence is present.
4. Items are processed in listed order. `dir` must be `from_client` or `from_server`; an invalid value causes an assertion and skips that item.
5. For an item with `protocol: QUIC`, the handler Base16-decodes `frame`, passes the bytes to `quic_packets::read(&quicsession, direction, bin_frame)`, checks the QUIC session's alerts, and records the return status with `_test_case.test`.
6. For `protocol: TLS 1.3`, the active code returns `errorcode_t::do_nothing`. The TLS-record parser call is commented out. Any other item-level protocol causes an assertion.
7. A fatal alert other than `certificate_unknown` marks the vector failed and stops item processing. A successful per-item status is not a byte-for-byte comparison against the original `.pcapng`, and the TLS 1.3 items are not actively decrypted/parsed by this handler.

The vector's `secrets` are SSLKEYLOG-style traffic-secret lines; they are not a raw packet capture or a pre-master-secret field. The fixture carries direction, item label, protocol and hexadecimal frame data. Comments in the YAML can annotate the recorded exchange, but the assertions come from the actual handler and the packet reader.

## 3. Evidence

### 3.1 Source-level verification paths

#### RFC 9000 integer and packet-number algorithms

```text
fixed RFC input bytes / integer
  -> quic_read_vle_int / quic_write_vle_int
  -> compare decoded integer or encoded bytes with expected value
  -> testcase assertion

full packet number + largest acknowledged
  -> encode_packet_number
  -> compare truncated value and bit count
  -> testcase assertion

truncated packet number + largest acknowledged + encoded bit width
  -> decode_packet_number
  -> compare reconstructed packet number
  -> testcase assertion
```

**Assertion strength:** explicit expected-value comparisons cover the listed RFC examples and boundary values. Error paths and the complete input space are not established by these vectors.

#### RFC 9001 / RFC 9369 packet protection

```RFC vector inputs
  -> initialize QUIC session / destination connection ID
  -> derive Initial secrets and packet protection material
  -> compare selected secrets, keys, IVs and HP keys
  -> construct protected packet
  -> compare payload, headers, packet bytes and selected metadata
  -> parse selected packet bytes and check selected results
```

**Assertion strength:** the active vector cases contain direct comparisons against fixed RFC values, including final packet bytes and selected header/metadata fields. This evidence applies to the vectors and fields actually asserted, not every QUIC packet type or all protocol state transitions.

#### QUIC Illustrated and 1-RTT examples

```
illustrated packet bytes / fixed 1-RTT secrets
  -> quic_read_packet or quic_packets::read
  -> inspect selected packet / return status
  -> explicit expected-value assertions where present
```

**Assertion strength:** the walkthrough mixes exact secret comparisons with packet-read status checks and diagnostic output. The 1-RTT testcase checks selected parsed fields and a constructed-packet round trip; neither path is a live peer-to-peer test.

#### PCAP SIMPLE replay

```
testvector_pcap_http3.yml
  -> schema dispatch: PCAP SIMPLE
  -> require vector protocol HTTP/3
  -> import optional SSLKEYLOG lines into TLS + QUIC sessions
  -> each item: direction + item protocol + frame bytes
  -> QUIC: quic_packets::read -> inspect alerts -> testcase status
  -> TLS 1.3: do_nothing (record parsing is inactive)
```

**Assertion strength:** the handler explicitly checks vector protocol, direction and item protocol, records per-item return status, and rejects fatal alerts except `certificate_unknown`. It does not replay raw `.pcapng` bytes, compare a complete reconstructed capture, or actively process the TLS 1.3 items.

### 3.2 Runtime report and verification path

The supplied [Test Report Snapshot](../test-report-status.md) records the `quic` group as **241 pass, 0 expt, 0 fail, 0 skip and 2 triv**. The associated run context supplied with the report is Revision 1104 on MinGW64/GCC using CTest. The report files do not independently identify the tested source commit, exact compiler version or full build configuration.

This is the last known report snapshot, not a fresh run for the current documentation revision. No tests were rerun during this documentation update. The counts are harness categories, not a count of unique test functions or proof of complete QUIC/HTTP/3 coverage.

## 4. Relationships

- `sdk/net/tls/quic/packet/` — QUIC packet encodings, packet protection and parsing.
- `sdk/net/tls/quic/frame/` — QUIC transport frames and frame parsing.
- `sdk/net/tls/` — TLS handshake and secret/key-schedule facilities used by QUIC.
- `sdk/net/http/http3/` — HTTP/3 frame layer.
- `sdk/net/http/qpack/` — QPACK header compression.
- `test/testcase/tls/` — separate TLS/DTLS test group; QUIC's TLS 1.3 record-vector branch is currently inactive.
- `test/testcase/quic/http3/` — recorded HTTP/3 capture, key-log material and experiment notes.
- `testcase_rfc9000.cpp`, `testcase_rfc9001.cpp`, `testcase_rfc9369.cpp`
- `testvector_pcap.cpp` and `testvector_pcap_http3.yml`

## 5. References

- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9369 — QUIC Version 2](https://www.rfc-editor.org/rfc/rfc9369)
- [QUIC Illustrated](https://quic.xargs.org/)

## 6. Developer Notes

- [Developer Notes - HTTP/3 capture and diagnostic material](http3/README.md) — artifact inventory and interpretation boundaries for the capture, key log and notes.
- [Developer Notes - HTTP/3 capture and curl client trace](http3/http3.md) — preserved curl output associated with the recorded `http3.pcapng` experiment.

The capture and SSLKEYLOG material may expose traffic secrets. Treat these as controlled test artifacts and do not interpret their presence as proof of a test pass or as a general-purpose fixture for unrelated traffic.
