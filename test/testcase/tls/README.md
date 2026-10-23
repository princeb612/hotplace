## Publication

```text
hotplace source tree
Edition 2 · Revision 1107
Source basis: Revision 1107
Documented with GPT-6
— testcase inputs, procedures & verification
```

# TLS and DTLS Testcases

## 1. What

`test/testcase/tls/` is the TLS/DTLS testcase group. Its entry point, `sample.cpp`, registers tests for TLS 1.2 and TLS 1.3 processing, DTLS construction and fragmentation, selected RFC 8448 handshake traces, pre-master/traffic-secret handling, TLS 1.2 AEAD record protection, ML-KEM encoding, alerts, HelloRetryRequest, and YAML-driven record replay.

This directory is not one end-to-end network interoperability test. Most executable cases drive implementation APIs with constructed or captured record bytes; separate subdirectories preserve packet captures and client/server debug logs from particular experiments.

The YAML-backed path uses the `PCAP SIMPLE` schema:

- **Input:** each vector chooses `TLS` or `DTLS`, may provide SSL key-log-style secrets, and supplies an ordered list of records with a peer direction and hexadecimal bytes.
- **Processing:** the consumer creates a new `tls_session` for each vector and feeds the listed records through `dump_record`.
- **Checks:** malformed `protocol` or `dir` values cause an assertion; fatal alerts normally cause a failed testcase, with an explicit exception for `certificate_unknown`. Empty or undecodable record bytes are skipped by the current implementation.

The group also includes tests that do not use YAML, such as constructed handshake flows, explicit secret/transcript-hash comparisons, RFC 8448 traces, and DTLS fragmentation-oriented construction.

PCAP files and their associated Markdown client/server logs are supporting experiment inventories, not separate CTest targets. The child READMEs are intentionally maintained as inventories of these artifacts. QUIC tests are separate under `test/testcase/quic/`.

## 2. How

### Test flow at a glance

```text
sample.cpp / testcase harness
             |
      registered test cases
             |
     +-------+-------------------+
     |                           |
direct API / fixed vectors    PCAP SIMPLE YAML
     |                           |
construct messages/keys      protocol + direction
or compare expected values   + record byte ranges
     |                           |
     +-------------+-------------+
                   |
       TLS / DTLS session processing
                   |
       +-----------+-----------+
       |                       |
 explicit assertions       status / diagnostic output
       |                       |
 expected-value evidence   limited evidence by itself

PCAP / peer logs / capture files -> experiment inventory
                                  (not separate CTest targets)
```

Use this map to distinguish a fixed expected-value assertion from a parser/status walkthrough or a stored capture. They provide different strengths of evidence.

### 2.1 Test dispatch and build inputs

1. The testcase entry point in `sample.cpp` initializes the shared testcase harness, logger, command-line options, and OpenSSL support.
2. In the normal test mode, it runs resource validation; TLS 1.3, TLS 1.2, and DTLS walkthroughs; selected RFC 8448 examples; pre-master-secret processing; TLS 1.2 AEAD and ML-KEM encoding; YAML record replay; HelloRetryRequest and alert cases; and TLS/DTLS record-construction tests.
3. The TLS directory's `CMakeLists.txt` collects top-level `.cpp` files into the `tls` testcase target and copies top-level `.yml` files into the build tree's TLS testcase directory.
4. `testvector_pcap.cpp` opens the copied YAML files by their configured filenames. The ML-KEM TLS 1.3 vector is included only when `OPENSSL_VERSION_NUMBER >= 0x30500000L`.
5. The PCAP and peer-log files in the version-specific subdirectories document recorded experiments; they are not added as individual CTest targets by this directory's CMake configuration.

### 2.2 TLS and DTLS handshake construction

1. In `testcase_construct_tls.cpp`, helper routines create a `tls_record_handshake` and ask `tls_composer` to construct messages such as `ClientHello` and `ServerHello`.
2. The constructed handshake is added to the record, then serialized with `record.write(direction, bytes)`. The testcase harness records the returned status for the named construction step.
3. Other construction paths build records such as ChangeCipherSpec, EncryptedExtensions, and Certificate under the session's applicable state/protection conditions.
4. The DTLS 1.2 cases use `construct_record_fragmented`, which delegates publishing to the session's DTLS record publisher. The resulting fragments are sent through the supplied callback/traffic path.
5. Read these as selected construction and state-transition examples, not as proof that every legal handshake sequence or malformed-message case is covered.

### 2.3 RFC 8448 and selected TLS protocol paths

1. `sample.cpp` invokes the selected `testcase_rfc8448_*` routines for RFC 8448 TLS 1.3 examples.
2. The examples feed fixed handshake/record data through the relevant TLS processing functions and check selected decoded results, key-schedule values, transcript hashes, or status/state values where the source explicitly asserts them.
3. `testcase_pre_master_secret.cpp` attaches the SSL key-log importer to a TLS session, imports fixed traffic-secret lines, then processes a fixed sequence of client and server records, including handshake and application-data records.
4. `testcase_helloretryrequest.cpp` exercises a constructed ClientHello/ServerHello exchange with an enforced key-share group, then checks selected session-status bits and the expected HelloRetryRequest flow before continuing with the second ClientHello.
5. `testcase_alert.cpp` exercises selected alert processing. The precise assertion strength depends on each individual case; diagnostic output alone is not an expected-value check.

### 2.4 TLS 1.2 record protection and ML-KEM encoding

1. `testcase_tls12_aead.cpp` exercises selected TLS 1.2 record-protection cases using the test inputs and session state prepared by the source.
2. The TLS test entry point also calls the ML-KEM encoding testcase. This is a separate encoding path from the YAML PCAP replay.
3. Check the individual source assertions before interpreting a case as a known-answer comparison, a state/status check, or a diagnostic demonstration. The cipher-suite inventory is not a substitute for inspecting which inputs and assertions each testcase actually uses.

4. In the ChaCha20-Poly1305 case, the source derives TLS 1.2 key-block values from fixed master-secret and random inputs, compares the client write key and IV with fixed expected bytes, and decrypts captured client/server Finished records against expected plaintext handshake bytes. This is targeted evidence for those exact values and records, not a full-handshake interoperability test.

### 2.5 PCAP SIMPLE YAML vectors

The authoritative schema example is kept here because `testvector_pcap.cpp` is the consumer for this format. The following is valid YAML-shaped input; `string` and `hexstring` are explanatory placeholders, not literal values.

```yaml
testvector:
  - example: string
    schema: PCAP SIMPLE
    protocol: TLS
    secrets:
      - item: string
    items:
      - item: string
        dir: from_client
        record: hexstring
```

1. The YAML runner dispatches each vector to the handler registered as `PCAP SIMPLE`.
2. The handler reads `protocol`. `TLS` creates a TLS session; `DTLS` creates a DTLS session. Any other value causes an assertion and stops processing that vector.
3. The handler clears the shared SSL key-log importer, attaches it to the new session, and imports each `secrets[].item` line when a secrets sequence is present.
4. It processes `items` in their listed order. Each item's `dir` must be `from_client` or `from_server`; an invalid value causes an assertion and ends that item's loop. `record` is Base16-decoded; an empty decoded record is skipped.
5. Each non-empty record is passed to `dump_record` with the selected direction. After processing, the handler checks for fatal alerts; `certificate_unknown` is explicitly exempted, while another fatal alert marks the testcase failed and stops the vector.
6. The runner currently loads `testvector_pcap_tls13.yml`, `testvector_pcap_tls12.yml`, `testvector_pcap_http.yml`, and `testvector_pcap_dtls12.yml`. It conditionally loads `testvector_pcap_tls13_mlkem.yml` with the OpenSSL version guard noted above.

Field meanings:

- `example` identifies the vector/testcase.
- `schema` selects the `PCAP SIMPLE` handler.
- `protocol` selects `TLS` or `DTLS`.
- `secrets` is an optional sequence of key-log-style secret lines.
- `items` is an ordered sequence of records; each record has a label (`item`), peer direction (`dir`), and hexadecimal bytes (`record`).

The handler does not enforce a separate full schema contract beyond the checks described above. In particular, an empty decoded record is skipped, and a vector's successful completion is not a byte-for-byte comparison of a full PCAP file against a newly captured network run.

### 2.6 Recorded experiment inventories

The following subdirectories retain their original inventory role: each README maps captures to the corresponding client/server logs and records useful experiment conditions. These are not rewritten as executable testcase procedures.

- [Developer Notes - TLS 1.2](tls12/README.md) — TLS 1.2 captures, peer logs, and selected record-protection/renegotiation experiments.
- [Developer Notes - TLS 1.3](tls13/README.md) — TLS 1.3 captures, selected AEAD and key-exchange variants, and a handshake-failure capture.
- [Developer Notes - DTLS 1.2](dtls12/README.md) — DTLS 1.2 captures, peer logs, and MTU-related experiments.
- [Developer Notes - HTTP over TLS](http/README.md) — HTTP/1.1, HTTP/2, trial-server, and curl capture inventory.
- [Developer Notes - Linux TLS](linux/README.md) — Linux loopback experiment conditions, commands, and peer diagnostics.

Where supplied, `sslkeylog` data contains session secrets used to decrypt the corresponding controlled captures. It is sensitive test material, not a general-purpose fixture to publish or reuse outside its intended test context. A capture and its associated peer logs document that recorded run only.

## 3. Evidence

### 3.1 Source-level verification paths

The diagrams below distinguish explicit expected-value comparisons from return-status checks and diagnostic output. They summarize the paths present in the source; they do not claim exhaustive coverage.

#### TLS 1.2 AEAD known-value path

```text
testcase_tls12_aead.cpp
  -> fixed cipher suite + client/server randoms + master secret
  -> tls_protection::calc_keyblock(...)
  -> compare client_key and client_iv with expected bytes
  -> decrypt selected encrypted client/server Finished records
  -> compare plaintext bytes with expected handshake encodings
```

**Assertion strength:** this case contains explicit comparisons for selected key-block outputs and decrypted Finished-message bytes. It does not independently prove all TLS 1.2 cipher suites, all nonce/AAD combinations, or all handshake transitions.

#### TLS/DTLS record construction

```text
testcase_construct_tls.cpp / DTLS construction sources
  -> create tls_session and record
  -> tls_composer constructs handshake message
  -> append handshake to record
  -> record.write(direction, bytes)
  -> testcase status check
```

**Assertion strength:** construction helpers record the returned status. Only cases with additional explicit assertions on bytes, state, secrets, or transcript hashes support those stronger claims; a successful write status alone does not prove the serialized bytes match a protocol known-answer vector.

#### RFC 8448, secret and transcript checks

```text
fixed RFC trace / key-log secret inputs
  -> feed record or handshake bytes into TLS session
  -> selected session/key-schedule processing
  -> where asserted:
       secret == Base16-decoded expected secret
       transcript hash == expected digest
       decoded values / flow / status == expected value
  -> testcase assertion
```

**Assertion strength:** the source includes exact comparisons for selected secrets and transcript hashes, plus selected state/status checks. These assertions apply only to the particular traces and values checked by each testcase.

#### HelloRetryRequest flow

```text
ClientHello with enforced initial key-share group
  -> server-side session consumes ClientHello
  -> assert selected ClientHello status
  -> server constructs retry response
  -> assert HelloRetryRequest flow and ServerHello status
  -> client sends second ClientHello with requested group
  -> assert subsequent server status and expected flow
```

**Assertion strength:** the testcase checks selected session-status bits and the expected flow transition for this constructed scenario. It does not prove every HelloRetryRequest negotiation combination.

#### PCAP SIMPLE vector replay

```text
testvector_pcap_*.yml
  -> yaml_testcase dispatch: schema "PCAP SIMPLE"
  -> protocol -> create TLS/DTLS session
  -> import optional SSL key-log secrets
  -> each item: direction + Base16 record bytes
  -> dump_record(session, direction, record)
  -> inspect session alerts
  -> fatal alert other than certificate_unknown -> failed testcase
```

**Assertion strength:** protocol/direction validation and fatal-alert handling are explicit checks. The handler skips empty decoded records and does not compare the entire PCAP with a separately generated capture. Do not interpret a vector's presence as proof that every contained handshake property is independently asserted.

### 3.2 Runtime report and verification path

The supplied [Test Report Snapshot](../test-report-status.md) records the `tls` group as **17,664 pass, 1 expt, 0 fail, 0 skip, 0 triv**. The associated run context is Revision 1104 on MinGW64/GCC using CTest. The report files do not independently identify the tested source commit, exact GCC version, or complete build configuration; treat this as group-level evidence for the supplied snapshot, not as a verified result for every individual testcase or the current source revision.

The documentation change did not execute tests. The source diagrams above describe inspected execution and assertion paths; they are not a new runtime result. When recording a new run, retain the source revision/commit, OS/compiler, build configuration, CTest command, date, and report archive context.

### 3.3 Verification boundaries

- The [Developer Notes - TLS study checklist and historical TODOs](test.md) records study history and TODOs; a checked item is not a current automated assertion or execution result.
- The [Developer Notes - TLS cipher-suite inventory](cipher-suites.md) is an inventory, not proof that every listed suite has a dedicated known-answer test.
- The [Developer Notes - TLS and DTLS packet-capture index](packet-capture.md) and version-specific capture inventories document selected observed runs; they do not establish universal interoperability.
- The [Developer Notes - TLS 1.3 handshake-flow sketch](tls13-flow.md) is a message-order study aid, not verification evidence.
- TLS/DTLS source coverage does not imply QUIC coverage; QUIC is tracked separately.

## 4. Relationships

- [Network testcase group](../net/README.md) — sibling protocol-test documentation pattern and related HTTP components.
- [TLS SDK implementation](../../../sdk/net/tls/README.md) — TLS/DTLS session, record, and handshake implementation.
- [OpenSSL-backed network adapters](../../../sdk/net/basic/openssl/README.md) — adapters used in some recorded peer experiments.
- [Cryptographic SDK](../../../sdk/crypto/README.md) — cryptographic primitives and key operations used by TLS paths.
- [QUIC testcases](../quic/README.md) — separate transport and packet verification.
- [HTTP testcases](../net/http/README.md) — HTTP framing and protocol components related to HTTP-over-TLS captures.
- [Test Report Snapshot](../test-report-status.md) — aggregate results and provenance limits.

- TLS testcase implementation sources: `sample.cpp`

## 5. References

- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
- RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2.
- RFC 9147 — The Datagram Transport Layer Security (DTLS) Protocol Version 1.3.
- [TLS 1.3 walkthrough](https://tls13.xargs.org/)
- [TLS 1.2 walkthrough](https://tls12.xargs.org/)
- [DTLS walkthrough](https://dtls.xargs.org/)
- [RFC 8448 — Example Handshake Traces for TLS 1.3](https://www.rfc-editor.org/rfc/rfc8448)


## 6. Developer Notes

These pages preserve study notes, historical checklists, capture inventories, and protocol-flow aids. They are intentionally separate from the executable testcase description above: use them when investigating a particular suite, recorded experiment, handshake sequence, or historical TODO. Their contents are supporting context, not standalone evidence that a current testcase passes.

- [Developer Notes - TLS cipher-suite inventory](cipher-suites.md) — cipher-suite identifiers and caveats about interpreting inventory as test coverage.
- [Developer Notes - TLS and DTLS packet-capture index](packet-capture.md) — capture locations, peer logs, inspection workflow, and key-log handling cautions.
- [Developer Notes - TLS study checklist and historical TODOs](test.md) — historical study progress and TODOs, including items that need current verification.
- [Developer Notes - TLS handshake construction and observation notes](test-construct-tls-routine.md) — reference message sequences and historical OpenSSL experiment commands.
- [Developer Notes - TLS 1.3 handshake-flow sketch](tls13-flow.md) — compact 1-RTT and 0-RTT message-order orientation.

The version-specific subdirectory inventories remain under their own `Developer Notes - ...` READMEs and are linked in [How §2.6](#26-recorded-experiment-inventories).
