### HTTP/3 capture and diagnostic material

This directory contains HTTP/3-oriented capture/diagnostic artifacts, including `http3.pcapng`, the `http3.md` notes and the `sslkeylog` material.

The capture and key-log files are useful for studying encrypted QUIC/HTTP/3 traffic with packet-analysis tools. They are diagnostic inputs, not executable proof that every HTTP/3 request path is implemented end to end.

For source-driven parsing/replay tests, also see `test/testcase/quic/testvector_pcap.cpp` and `testvector_pcap_http3.yml`. That test path reads capture/test-vector data; keep it distinct from tests that open a live HTTP/3 connection and assert application-level request/response behavior.

The protocol implementation is split across:
- `sdk/net/tls/quic/packet/` — QUIC packet structures and protection-aware parsing/writing.
- `sdk/net/tls/quic/frame/` — QUIC transport frames and HTTP/3 stream bridge.
- `sdk/net/http/http3/` — HTTP/3 frames.
- `sdk/net/http/qpack/` — header field compression.
