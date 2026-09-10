# TLS

> Edition 1 · Revision 1072  
> Documented with GPT-5.6 Luna — study, reconstruction & review

## Context

TLS is one of the most connected protocol areas in hotplace. It is not treated only as an encryption helper; it sits between transport, handshake, certificate, application protocol, and QUIC-related processing. The current study therefore connects TLS with TCP, UDP/DTLS, QUIC, HTTPS, ASN.1/X.509, and the KEM/PQC study area.

```text
                         ASN.1
                           │
                      X.509 / cert
                           │
                           ▼
TCP ───────────────────── TLS ─────────────────── HTTPS
                           │
                ┌──────────┼──────────┐
                │          │          │
                ▼          ▼          ▼
              DTLS        QUIC      KEM/PQC
                │          │
               UDP       HTTP/3
```

The important context is the path by which these topics meet. HPACK/QPACK study led into HTTP/2 and HTTP/3, while QUIC required a deeper understanding of TLS 1.3 handshake messages, extensions, key schedule, and packet protection. TLS/X.509 structures in turn brought ASN.1 back into focus.

## History

The available development record shows TLS becoming a central study area while QUIC was being developed. The study moved from protocol understanding and concrete TLS handshake construction toward the cryptographic protection required by QUIC. During this process, TLS 1.2 and TLS 1.3 were examined, RFC 8448 examples were constructed, handshake extensions and HelloRetryRequest were explored, and packet-level traces were used for verification.

The TLS work also exposed the relationship between certificates/X.509 and ASN.1. ASN.1 was later revisited as an independent topic and is currently still under runtime development. QUIC packet/frame work and PCAP-based study have progressed substantially; the remaining work includes the `trial_tls_composer` handshake path and integration with `network_server`. These are recorded as current status rather than treated as completed design.

## Conceptual

### TLS as a protocol boundary

TLS coordinates negotiation, authentication-related material, handshake state, transcript state, key schedule, and protected application data. Encryption and decryption are only one part of that boundary.

### TLS 1.2 and TLS 1.3

The project studies both versions, with TLS 1.3 being particularly important to QUIC. The distinction matters because QUIC does not simply carry ordinary TLS records; TLS handshake messages are carried through QUIC CRYPTO frames and the resulting secrets drive QUIC packet protection.

### TLS and its neighboring protocols

- **TCP ↔ TLS**: TLS runs over a reliable byte stream.
- **UDP ↔ DTLS**: DTLS provides the TLS-style security model over datagrams while accounting for datagram transport behavior.
- **TLS ↔ QUIC**: QUIC uses TLS 1.3 for the handshake and derives packet-protection keys from the TLS key schedule.
- **TLS ↔ HTTPS**: HTTPS is the application-facing use of HTTP over a TLS-protected transport.
- **TLS ↔ ASN.1/X.509**: certificate structures introduce ASN.1-defined data into the TLS study.
- **TLS ↔ KEM/PQC**: key-establishment mechanisms form a connected cryptographic study area.

## Structural

The current implementation separates TLS protocol composition, cryptographic protection, secure byte processing, and transport/socket integration.

```text
TLS handshake composition
        │
        ├── TLS session state
        ├── handshake messages / extensions
        └── QUIC handshake composition
                 │
                 ▼
          QUIC CRYPTO frames

TLS protection
        │
        ├── negotiation
        ├── transcript
        ├── key schedule / secrets
        └── encrypt / decrypt

secure byte processing
        │
        ├── TLS / DTLS record processing
        └── QUIC protected packet processing

transport integration
        │
        ├── TCP / TLS
        ├── UDP / DTLS
        └── QUIC
```

Current source anchors include `sdk/net/basic/trial/tls_composer.hpp`, `sdk/net/basic/trial/tls_composer_quic_handshake.cpp`, `sdk/net/tls/`, and `sdk/net/tls/quic/`. The transport-facing trial socket path is represented by `trial_tls_server_socket` and related server-socket abstractions. These names are navigation anchors; the conceptual roles above are the stable description.

## Flow

### TCP + TLS

```text
TCP byte stream
    ↓
TLS handshake
    ↓
TLS session / protection state
    ↓
protected application data
```

### UDP + DTLS

```text
UDP datagrams
    ↓
DTLS handshake / record processing
    ↓
DTLS protection state
    ↓
application data
```

### TLS + QUIC

```text
TLS handshake message
    ↓
QUIC CRYPTO frame
    ↓
QUIC packet
    ↓
packet protection
    ↓
peer receives / processes TLS handshake
```

The QUIC path is the important structural distinction: TLS remains responsible for handshake semantics and key establishment, while QUIC owns packetization, transport frames, packet number spaces, and packet protection integration.

## Study & Verification

The study material is organized around the questions that shaped the implementation rather than around testcase names.

### TLS protocol understanding and construction

TLS 1.2 and TLS 1.3 behavior was studied through dedicated understanding and construction cases. The current verification anchors include `testcase_understand_tls12`, `testcase_understand_tls13`, and `testcase_construct_tls`.

### RFC 8448 examples

Concrete TLS 1.3 handshake examples from RFC 8448 were reconstructed through `testcase_rfc8448_2` through `testcase_rfc8448_7`. These cases serve as executable protocol study material, connecting specification values with the implementation's handshake construction and cryptographic state.

### Cryptographic protection

AEAD processing, pre-master-secret handling, transcript-related state, and key derivation were explored through cases including `testcase_tls12_aead` and `testcase_pre_master_secret`.

### Extensions and HelloRetryRequest

Handshake extension processing and HelloRetryRequest behavior were examined through `testcase_helloretryrequest`, providing a concrete trace for the less-linear TLS 1.3 handshake path.

### Packet traces / PCAP

PCAP-based vectors are used to connect abstract protocol understanding with real wire-level behavior. `testvector_pcap` is the current source anchor for this part of the study.

## Status

| Area | Current state |
|---|---|
| TLS 1.2 | implemented / studied |
| TLS 1.3 | implemented / studied |
| Handshake composition | substantial |
| Cryptographic protection | substantial |
| DTLS path | implemented / studied |
| QUIC / TLS relationship | substantial |
| QUIC packet / frame work | substantial |
| QUIC PCAP study | completed as a study stage |
| `trial_tls_composer` handshake | remaining |
| `network_server` integration | remaining |
| ASN.1 runtime | separate ongoing topic |
| KEM / PQC | connected study area |

## Related Documents

The relationships are intentionally kept small at this stage and can grow with the document set.

```text
TLS
├── ASN.1 / X.509
├── HTTP / HTTPS
├── DTLS
├── QUIC
│   └── HTTP/3
└── KEM / PQC
```

Current related topics: HPACK, HTTP/2, and the planned ASN.1, QUIC, HTTP/3, and QPACK documents.

---

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1072            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
