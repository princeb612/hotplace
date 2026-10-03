# Hotplace TLS → DTLS → QUIC Development Path

> **Review baseline:** Revision 1096

The TLS, DTLS, and QUIC work is best understood as a development path rather than three unrelated implementations.

```text
TLS
 ↓
crypto / key-schedule understanding
 ↓
record / handshake / extensions
 ↓
DTLS
 ↓
datagram-specific concerns
 ↓
QUIC
 ↓
TLS integration + UDP transport
```

External protocol examples and test vectors made intermediate-value comparison important. The key schedule became a useful checkpoint:

```text
input secrets
     ↓
handshake secrets
     ↓
traffic secrets
     ↓
key / IV
```

TLS work expanded into records, handshake messages, extensions, and negotiated parameters. The CBC-HMAC / EtM area became a separate investigation because record protection details interact in subtle ways.

DTLS introduced datagram concerns such as loss, reordering, and retransmission. QUIC then combined UDP transport, packet construction, session handling, and TLS handshake integration.

The important point is not a simple linear feature checklist: earlier abstractions and discoveries were reused in later protocol work.

### Related source / documents

- TLS / DTLS / QUIC implementations
- `cbc-hmac-survey.md`
- binary construction documentation
- network session documentation
- crypto advisor/dictionary documentation

---

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1096                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
