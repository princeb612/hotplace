## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: QUIC capture/vector test material
```

# QUIC testcase material

## 1. Role

This directory preserves QUIC protocol references, packet-capture/test-vector material, and the schema used by the simplified PCAP vector reader. These fixtures support source-driven parsing/replay investigations; they are not a claim that a live QUIC/HTTP/3 client/server path is fully implemented or tested end to end.

## 2. Test model

The retained protocol references include RFC 9000, RFC 9001 and RFC 9369, plus the QUIC Illustrated resource. The simplified `PCAP SIMPLE` schema is an ordered test-vector format, not a generic five-tuple PCAP schema.

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
        record: hexstring
        frame: hexstring
```

## 3. Example: capture-vector item

A vector identifies the direction (`from_client` or `from_server`) and whether the item is marked as `QUIC` or `TLS 1.3`. The `secrets` section contains SSLKEYLOG-style traffic-secret entries, not a pre-master secret. The reader imports those entries into an `sslkeylog_importer` attached to separate TLS and QUIC session objects.

The current consumer has an important boundary: `protocol: QUIC` decodes the `frame` field and passes it to `quic_packets::read(&quicsession, direction, bin_frame)`, then checks whether the session reported a fatal alert. The `protocol: TLS 1.3` branch currently returns `errorcode_t::do_nothing`; the commented-out TLS record parsing is not active. Therefore this YAML path is not a full replay engine for every TLS/QUIC item represented in a capture.

The supplied `testvector_pcap_http3.yml` records a captured HTTP/3 exchange: Initial/Handshake CRYPTO frames, ACK activity across protection spaces, then 1-RTT STREAM traffic and HTTP/3-related activity. Its comments serve as capture annotations; the testcase's actual assertions are the per-item result checks and fatal-alert check. This is capture-driven parser/diagnostic coverage, not a live socket test that asserts an HTTP/3 request/response end to end.

## 4. Test and verification status

### 4.1 Source-level coverage

The directory documents fixture schema and protocol examples. Exact parser/replay coverage is determined by the C++ vector consumer and its assertions.

### 4.2 Documentation and verification status

The fixtures and references are retained for study and test reproduction. This README does not claim that they were executed during this documentation pass or that every QUIC version/packet type is covered.

## 5. Relationships

- `sdk/net/tls/quic/packet/` — QUIC packet structures.
- `sdk/net/tls/quic/frame/` — QUIC transport frames.
- `sdk/net/http/http3/` — HTTP/3 frame layer.
- `sdk/net/http/qpack/` — QPACK header compression.
- `test/testcase/quic/http3/` — HTTP/3 capture/diagnostic material.

## 6. References

- RFC 9000 — QUIC
- RFC 9001 — Using TLS to Secure QUIC
- RFC 9369 — QUIC Version 2
- [QUIC Illustrated](https://quic.xargs.org/)
- `testvector_pcap.cpp`
- `testvector_pcap_http3.yml`

## Latest recorded runtime report

The latest shared report snapshot is indexed in [Test Report Snapshot](../test-report-status.md). It records 241 pass, 0 expt, 0 fail, 0 skip and 2 triv entries for the `quic` group. The associated run context supplied in the conversation is Revision 1104 on MinGW64/GCC with CTest; the report payload does not independently identify the tested source commit or exact build configuration. Keep this as the last known result until a newer report is supplied. This summary does not establish live QUIC/HTTP/3 end-to-end coverage.
