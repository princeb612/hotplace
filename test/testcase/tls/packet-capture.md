# TLS and DTLS packet-capture references

The capture subdirectories keep recorded protocol exchanges alongside client/server notes and, where applicable, TLS key-log material.

- [TLS 1.3](tls13/README.md)
- [TLS 1.2](tls12/README.md)
- [DTLS 1.2](dtls12/README.md)
- [HTTP over TLS](http/README.md)
- [Linux-specific captures](linux/README.md)

Use the client/server notes to identify how each capture was produced and which side's output is being shown. A PCAP is a fixed observation of one run; it is not a general conformance test or evidence that all cipher suites, platforms, or peer implementations interoperate.

**Key-log caution:** TLS key-log files can enable decryption of the corresponding captured session. Treat them as test artifacts, keep them paired with their capture, and do not reuse or publish secrets from real sessions.
