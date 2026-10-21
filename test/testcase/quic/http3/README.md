## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: HTTP/3 capture and diagnostic material
```

# HTTP/3 capture and diagnostic material

## 1. Role

This directory contains HTTP/3-oriented capture/diagnostic artifacts, including `http3.pcapng`, `http3.md` notes and SSLKEYLOG material. These files support packet analysis and study; they are not executable proof that every HTTP/3 request path is implemented end to end.

## 2. Test model

The capture and key-log files are diagnostic inputs. For source-driven parsing/replay tests, the relevant path is `test/testcase/quic/testvector_pcap.cpp` with `testvector_pcap_http3.yml`. Keep fixture parsing distinct from tests that open a live HTTP/3 connection and assert application-level request/response behavior.

## 3. Example: inspect a captured HTTP/3 exchange

The capture can be analyzed with the associated key-log material in a packet-analysis tool. The source vector path reads capture/test-vector data, while the capture itself documents one recorded scenario. Neither one alone establishes full HTTP/3 interoperability.

## 4. Test and verification status

### 4.1 Source-level coverage

The directory is capture/diagnostic material. The executable vector consumer is located in the parent QUIC testcase directory; the current inventory does not identify this directory as a separate live HTTP/3 test executable.

### 4.2 Documentation and verification status

Do not treat the existence of a PCAP or SSLKEYLOG file as a test pass. Key logs and captures may expose traffic secrets; keep them confined to controlled test data, especially if captures ever contain real traffic.

## 5. Relationships

- `../testvector_pcap.cpp` and `../testvector_pcap_http3.yml` — source-driven vector path.
- `sdk/net/tls/quic/packet/` — QUIC packet processing.
- `sdk/net/tls/quic/frame/` — QUIC frame processing.
- `sdk/net/http/http3/` — HTTP/3 frame representation.
- `sdk/net/http/qpack/` — QPACK field compression.

## 6. References

- `http3.pcapng`
- `http3.md`
- `sslkeylog`
- [QUIC testcase material](../README.md)
