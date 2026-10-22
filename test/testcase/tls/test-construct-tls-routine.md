# Developer Notes - TLS handshake construction and observation notes

This page records handshake message sequences and the OpenSSL commands used in the original local experiments. It is a study aid for reading traces, not a normative protocol specification or a guaranteed copy-and-paste recipe for every OpenSSL version.

## TLS 1.3 reference sequence

The `tls13.xargs.org` walkthrough records the usual full-handshake progression:

1. Client → Server: `ClientHello`
2. Server → Client: `ServerHello`
3. Server → Client: `ChangeCipherSpec` (compatibility message in common traces)
4. Server → Client: `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`
5. Client → Server: `Finished`
6. Server → Client: `NewSessionTicket` may follow after the handshake

The precise presence and ordering of optional messages depends on the negotiated path. See [TLS 1.3 flow](tls13-flow.md) for the abbreviated 1-RTT and 0-RTT sketches.

## TLS 1.2 reference sequence

The `tls12.xargs.org` walkthrough records a certificate-based full handshake:

1. Client → Server: `ClientHello`
2. Server → Client: `ServerHello`, `Certificate`, `ServerKeyExchange`, `ServerHelloDone`
3. Client → Server: `ClientKeyExchange`, `ChangeCipherSpec`, `Finished`
4. Server → Client: `NewSessionTicket` may appear, followed by `ChangeCipherSpec` and `Finished`

This is a representative exchange, not a template for PSK, resumption, renegotiation, or every cipher suite.

## DTLS 1.2 reference sequence

The DTLS walkthrough adds the cookie exchange before the main handshake:

1. Client → Server: initial `ClientHello`
2. Server → Client: `HelloVerifyRequest`
3. Client → Server: `ClientHello` with the cookie
4. The TLS 1.2-style certificate handshake proceeds over DTLS records, with datagram-specific sequencing and possible fragmentation/retransmission behavior.

The sequence alone does not demonstrate fragmentation or loss recovery; inspect the corresponding DTLS capture or construction testcase for those behaviors.

## Local OpenSSL experiments

The historical notes used commands in this general form:

```sh
openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug
openssl s_client -connect localhost:9000 -state -debug
```

The original command variants added version-selection flags such as `-tls1_2`, `-tls1_3`, or `-dtls1_2`, and sometimes `-keylogfile sslkeylog`. The old notes also combine option flags across versions; check `openssl s_server -help` and `openssl s_client -help` for the installed build before reproducing a run. In particular, do not assume a TLS 1.2 cipher-suite name is a valid TLS 1.3 cipher-selection argument.

## Relationship to the source tests

- `testcase_construct_tls.cpp` uses `tls_composer` to create handshake messages, appends them to records, and serializes in a selected direction.
- `testcase_construct_dtls12_1.cpp` and `testcase_construct_dtls12_2.cpp` exercise DTLS 1.2 record construction and fragmentation through `udp_traffic`.
- `testcase_construct_dtls13.cpp` constructs DTLS 1.3 handshake/ciphertext records.
- `testcase_rfc8448_*.cpp` use fixed protocol bytes and key material to examine selected TLS 1.3 examples.
- `testvector_pcap.cpp` follows a different path: it replays YAML-described records through a `tls_session`.

Start from the [TLS testcase README](README.md) for the full source inventory and the distinction between executable assertions and recorded packet observations.
