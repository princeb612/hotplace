# Developer Notes - TLS and DTLS packet-capture index

The capture folders preserve selected protocol exchanges together with client/server command output. They are complementary to the executable C++ testcases: a capture is a record of one experiment, while a testcase exercises a code path under the test harness.

## Capture groups

- [TLS 1.2](tls12/README.md) — cipher-suite variants, CBC protection arrangements, and renegotiation/no-renegotiation examples.
- [TLS 1.3](tls13/README.md) — AEAD suites, key-exchange variants including ML-KEM combinations, and a handshake-failure case.
- [DTLS 1.2](dtls12/README.md) — datagram handshake traces, named cipher suites, and MTU/network-client experiments.
- [HTTP over TLS](http/README.md) — HTTP/1.1 and HTTP/2 traffic, including regular and trial server paths.
- [Linux-specific capture](linux/README.md) — a historical Ubuntu 20 loopback experiment with OpenSSL and the project netclient.

Each folder's README pairs a capture filename with the available client/server notes. The note files often contain verbose OpenSSL or hotplace diagnostics; use them to inspect the exact observed message order, record bytes, negotiated parameters, and errors rather than treating the filename as a complete description.

## How to interpret a capture

1. Read the version-specific README to locate the PCAP and its corresponding peer notes.
2. Check the command line, peer implementation, protocol version, and cipher suite recorded in the notes.
3. Use Wireshark or another packet analyzer to inspect record boundaries and handshake order. Where a matching key-log file is supplied, configure it only for this controlled test capture.
4. Compare the observed exchange with the corresponding executable testcase or the protocol-flow notes. Distinguish an observation from an assertion made by the test harness.

A PCAP represents a fixed run. It does not establish that every extension, alert path, operating system, crypto backend, or independent peer implementation behaves identically.

## Key-log and secret handling

TLS key-log files can allow packet analyzers to decrypt the corresponding captured session. Some detailed trace notes also include ephemeral key material or derived secrets. These are test artifacts; do not use real-session secrets, and review secret-bearing material before republishing captures or logs. Preserve capture and key-log pairing only where needed for the intended reproducible test.
