# PCAPNG — Study & Verification

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1076            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```

## Context

PCAPNG is not treated as a binary collection to be packaged with the documentation. The repository captures are **development and verification traces** connecting implementation work with real wire traffic.

The large `.pcapng` files remain in the source repository. This document records their role and provides source-relative anchors.

## Conceptual

The actual development loop is closer to:

```text
                protocol study
                     │
                     ▼
               implementation
                     │
                     ▼
                 trial TLS
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        curl     openssl      applet
                  s_client
          │          │          │
          └──────────┼──────────┘
                     ▼
                PCAPNG capture
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
      debug evidence       packet analysis
      sslkeylog match
          │                     │
          └──────────┬──────────┘
                     ▼
              implementation
                verification
                     │
                     ▼
               capture-replay
                     │
                     ▼
              regression vector
```

There are therefore two distinct uses.

### Development capture

During implementation, a capture records what the newly developed protocol stack actually did on the wire.

For the trial TLS server, the repository contains traces where the server is started with the trial adapter (`-T`) and then exercised by external clients.

Example:

```text
test/testcase/tls/http/
  curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.pcapng
  README_curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_server.md
  README_curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_client.md
```

The server-side debug trace records:

```text
./test-httpserver1.exe -r --debug -T   -cs TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -k &
```

The corresponding client trace records the real curl invocation with `SSLKEYLOGFILE`, making the capture useful not only as packets but as a cross-check between encrypted traffic, negotiated parameters, and debug output.

The same pattern appears in the ML-DSA server captures:

```text
test/applet/tlsserver/pcap/
  tlsserver-mldsa.pcapng
  README_server-mldsa.md

test/applet/httpserver1/pcap/
  httpserver1-mldsa.pcapng
  README_server-mldsa.md

test/applet/httpserver2/pcap/
  httpserver2-mldsa.pcapng
  README_server-mldsa.md
```

The server traces explicitly show the trial adapter:

```text
./test-tlsserver.exe -r -d -T -cert mldsa &
./test-httpserver1.exe -r -d -T -cert mldsa &
./test-httpserver2.exe -r -d -T -cert mldsa &
```

These README files are important because they preserve the surrounding execution/debug context that a binary capture alone cannot explain.

### Capture analysis

The accompanying markdown traces contain detailed protocol records, handshake decoding, cipher/group selection, and application traffic. In the TLS HTTP example, the client side uses:

```text
SSLKEYLOGFILE=sslkeylog curl ...
```

while the server-side trace records the trial TLS processing and negotiated cipher suite.

This creates a particularly valuable three-way correspondence:

```text
wire capture
     ↕
sslkeylog
     ↕
trial TLS debug trace
```

That correspondence is a living development artifact: it lets implementation changes be compared against both protocol semantics and observed traffic.

## Capture-Replay

Once real traffic became useful and stable, some captures were promoted into reproducible test vectors.

The central implementation is:

```text
test/testcase/tls/testvector_pcap.cpp
```

The TLS PCAP test runner imports SSL key-log material, attaches it to a TLS session, reads the YAML-described capture records, and replays the recorded traffic through the implementation.

The current YAML vectors include:

```text
testvector_pcap_dtls12.yml
testvector_pcap_http.yml
testvector_pcap_tls12.yml
testvector_pcap_tls13.yml
testvector_pcap_tls13_mlkem.yml
```

Representative captures include:

```text
test/testcase/tls/dtls12/dtls12.pcapng

test/testcase/tls/http1.pcapng

test/testcase/tls/tls12/
  tls12etm_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.pcapng

test/testcase/tls/tls13/
  tls13_TLS_AES_128_GCM_SHA256.pcapng

test/testcase/tls/tls13/
  tls13_TLS_AES_128_CCM_SHA256_MLKEM512.pcapng
```

The MLKEM vector set extends the same capture-replay idea across multiple TLS 1.3 hybrid groups. This is an important sign that PCAP-based verification became part of the implementation's regression machinery rather than remaining only a debugging convenience.

## Development → Verification

The resulting history can be summarized as:

```text
early protocol development
          ↓
       capture
          ↓
 packet/debug analysis
          ↓
 trial TLS server
          ↓
 real client verification
 curl / openssl s_client
          ↓
 PCAPNG + README + sslkeylog
          ↓
 stable capture selected
          ↓
 testvector_pcap
          ↓
 capture-replay
          ↓
 regression / side-effect verification
```

This is the meaningful role of PCAPNG in hotplace: it connects implementation work, real external interoperability, debugging evidence, and later regression testing.

## Source anchors

The binary captures remain outside the documentation package. Use the repository paths below to reach them:

```text
test/testcase/tls/http/
test/testcase/tls/dtls12/
test/testcase/tls/tls12/
test/testcase/tls/tls13/

test/testcase/tls/testvector_pcap.cpp
test/testcase/tls/testvector_pcap_dtls12.yml
test/testcase/tls/testvector_pcap_http.yml
test/testcase/tls/testvector_pcap_tls12.yml
test/testcase/tls/testvector_pcap_tls13.yml
test/testcase/tls/testvector_pcap_tls13_mlkem.yml

test/applet/tlsserver/pcap/
test/applet/httpserver1/pcap/
test/applet/httpserver2/pcap/
```

A separate QUIC/HTTP/3 capture path also exists:

```text
test/testcase/quic/http3/http3.pcapng
```

It should be read together with the QUIC/HTTP/3 study material rather than interpreted as proof of a complete HTTP/3 implementation.

## Status

- Large PCAPNG binaries are **not included in the docs package**.
- Source-relative paths are retained as navigation anchors.
- Development captures document real trial TLS/server verification.
- `curl` and `openssl s_client` provide external interoperability checks.
- `-T` traces identify the trial TLS adapter path.
- README/debug traces preserve surrounding execution context.
- SSL key-log material connects encrypted captures with TLS processing.
- `testvector_pcap.cpp` and YAML vectors provide capture-replay regression coverage.
- TLS 1.2, TLS 1.3, DTLS 1.2, HTTP, and TLS 1.3 MLKEM captures participate in this verification history.

PCAPNG is therefore best understood as a **development → interoperability → analysis → regression** artifact.
