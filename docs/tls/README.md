# TLS

> Edition 1 · Revision 1084  
> Documented with GPT-5.6 Luna — study, reconstruction & review

## Context

TLS is one of the largest protocol study areas in hotplace. It is not implemented as a single encryption component. The implementation spans protocol records, handshake messages, extensions, session state, transcript processing, key negotiation, key schedule, record protection, DTLS-specific processing, QUIC integration, and transport-facing handshake orchestration.

The most useful way to understand the implementation is to separate three questions:

```text
What is on the wire?
        ↓
How does the handshake change session meaning?
        ↓
Which cryptographic state protects the next bytes?
```

Those questions map to different layers of the source rather than to one monolithic TLS class.

```text
                    TLS session
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
   wire protocol    handshake/state   protection
        │               │                │
     record         extensions       secrets
     handshake      negotiation      transcript
     extension      authentication   key/IV
        │               │             encrypt/decrypt
        └───────────────┼────────────────┘
                        │
                  transport use
              TCP / DTLS / QUIC
```

## History

The CHANGELOG places TLS development across several distinct study stages.

- Revisions 650–672: direct TLS/DTLS understanding, including `tls13.xargs.org`, `tls12.xargs.org`, and `dtls.xargs.org`.
- Revisions 673–680: RFC 8448 TLS 1.3 handshake examples, including HelloRetryRequest, resumed 0-RTT, client authentication, and compatibility mode.
- Revisions 682–776: TLS/DTLS client-side development and network integration.
- Revisions 777–804: server integration with TLS, HTTP/1.1, and HTTP/2.
- Revisions 740–789: TLS 1.2 protection, certificates, CBC/GCM/CCM, Extended Master Secret, and key-share related work.
- Revisions 762–781: DTLS reconstruction, fragmentation, and cipher testing.
- Revisions 788–902: broader TLS 1.2/TLS 1.3 cipher and key-exchange coverage.
- Revisions 889–902: PQC/KEM work and TLS 1.3 ML-KEM hybrid groups.
- Revision 905: DTLS built-in reorder support.
- Revisions 953 and 999: TLS 1.3 ML-DSA certificate study and subsequent SLH-DSA study.
- Revision 994: TLS/HTTP/2/QUIC rollback checkpoint.
- Revision 1015 onward: renewed DTLS/TLS verification and cross-platform testing.

The chronology shows TLS evolving from protocol understanding into a reusable protocol/cryptographic implementation, then becoming a dependency for QUIC. The current source retains all of those layers.

## Conceptual

### TLS is a state-changing protocol, not only encryption

A TLS record can carry handshake, alert, change-cipher-spec compatibility traffic, or application data. Reading a record can therefore change the interpretation of subsequent records.

```text
record
  ↓
handshake message
  ↓
session negotiation
  ↓
transcript / secrets / protection state
  ↓
next record is interpreted under new state
```

The encryption operation is consequently downstream of protocol state.

### Three interacting state domains

The implementation can be understood as three related state domains:

```text
Protocol state
  ├─ TLS version
  ├─ negotiated cipher suite
  ├─ handshake message status
  ├─ extensions / selected parameters
  └─ alerts

Cryptographic state
  ├─ transcript hash
  ├─ pre-master / shared secret
  ├─ traffic secrets
  ├─ key / IV
  └─ record number / protection space

Transport framing state
  ├─ TLS record boundaries
  ├─ DTLS epoch / sequence
  ├─ DTLS handshake fragmentation
  └─ QUIC packet number space
```

`tls_session` is the meeting point of these domains; the concrete wire structures remain in record, handshake, extension, and QUIC modules.

### TLS 1.2 and TLS 1.3 are different protection models

TLS 1.2 retains the older master-secret/key-block model and supports CBC/HMAC as well as AEAD suites. TLS 1.3 uses a transcript-driven HKDF key schedule and traffic secrets, with AEAD record protection.

The implementation therefore keeps the common session/protection interface while branching internally according to version and protection mode.

### TLS and QUIC share the handshake, not the record layer

QUIC uses TLS 1.3 handshake semantics and key schedule, but does not carry TLS handshake messages inside ordinary TLS records.

```text
TLS over TCP
    TLS handshake
        ↓
    TLS record
        ↓
    TCP stream

TLS inside QUIC
    TLS handshake bytes
        ↓
    QUIC CRYPTO frame
        ↓
    QUIC packet
        ↓
    QUIC packet protection
```

This distinction explains why `tls_session` and `tls_protection` are reusable from the QUIC implementation while TLS record classes remain separate from QUIC packet classes.

## Structural

### The TLS implementation layers

```text
tls_session
     │
     ├── protection_context
     │      └── negotiation
     │
     ├── tls_protection
     │      ├── transcript
     │      ├── key schedule
     │      ├── secrets
     │      └── encryption / decryption
     │
     ├── tls_handshake
     │      └── concrete handshake messages
     │
     ├── tls_extension
     │      └── concrete extensions
     │
     ├── tls_record
     │      └── record content types
     │
     └── transport-specific session support
            ├── DTLS
            └── QUIC
```

The class names are useful navigation anchors, but the stable structure is **session → protocol objects → cryptographic protection → transport integration**.

### Record layer

`tls_record` owns the record boundary and common header/protection handling. Concrete record classes represent content types such as handshake, alert, application data, and compatibility change-cipher-spec traffic.

```text
incoming bytes
      ↓
tls_record::read()
      ↓
record header
      ↓
record body
      ↓
optional decrypt
      ↓
content-specific reader
```

For writing, the direction is reversed:

```text
content object
      ↓
record body
      ↓
record protection
      ↓
record header
      ↓
wire bytes
```

The record layer therefore connects protocol framing to cryptographic protection.

### Handshake layer

`tls_handshake` provides the common lifecycle:

```text
read/write
   ↓
header
   ↓
preprocess
   ↓
body
   ↓
postprocess
   ↓
scheduled follow-up work
```

Concrete classes implement message-specific bodies such as ClientHello, ServerHello, Certificate, CertificateVerify, EncryptedExtensions, Finished, NewSessionTicket, and the TLS 1.2 key-exchange messages.

The important point is that `do_postprocess()` is not merely cleanup. Handshake processing can update transcript state, derive secrets, change protection state, schedule extensions, or affect the next handshake action.

### Extension layer

Extensions are modeled as another protocol object family below handshake messages.

```text
Handshake
   │
   └── extension vector
          ├── supported_versions
          ├── supported_groups
          ├── key_share
          ├── signature_algorithms
          ├── server_name
          ├── ALPN
          ├── PSK
          ├── early_data
          ├── QUIC transport parameters
          └── other / unknown
```

This is important because TLS 1.3 moves much of the negotiation surface into extensions. The extension classes therefore participate in both wire decoding and semantic negotiation.

### Negotiation

`protection_context` stores the offered/available cryptographic parameters and performs selection.

```text
ClientHello
   ├── cipher suites
   ├── supported versions
   ├── supported groups
   ├── signature algorithms
   └── key-share groups
             │
             ▼
      protection_context
             │
             ▼
      negotiated parameters
```

The result feeds `tls_protection`, which then uses the selected version, cipher suite, hash, and key-exchange material to establish cryptographic state.

### Transcript and key schedule

`tls_protection` owns the bridge between handshake semantics and cryptographic state.

For TLS 1.3 the implementation follows the conceptual sequence:

```text
ClientHello / ServerHello
          ↓
      key agreement
          ↓
      shared secret
          ↓
      early / handshake secrets
          ↓
  client/server handshake traffic secrets
          ↓
       application secrets
          ↓
        key + IV
          ↓
       record/packet protection
```

The transcript hash is part of this calculation rather than an independent logging feature.

For TLS 1.2 the path is different:

```text
pre-master secret
      ↓
master secret
      ↓
key block
 ├── client MAC secret
 ├── server MAC secret
 ├── client write key
 ├── server write key
 ├── client IV
 └── server IV
```

The common protection object hides these version-specific derivation paths behind the session.

### Protection and encryption

The protection implementation separates:

```text
tls_protection
   ├── negotiation
   ├── transcript
   ├── secret calculation
   └── protection API
          │
          ├── AEAD
          ├── CBC/HMAC
          └── header/AAD/IV construction
```

The AEAD implementation is therefore not the TLS protocol itself. It consumes protocol-derived keying material and record metadata.

For TLS 1.2, AAD incorporates sequence number, content type, version, and length. DTLS additionally incorporates epoch and the datagram sequence number.

### Session as the state hub

`tls_session` keeps per-direction information, protection status, record numbers, alerts, scheduled handshakes/extensions, and the selected session type:

```text
tls_session
 ├── direction[client/server]
 │    ├── handshake status
 │    ├── protection enabled
 │    ├── record number / packet space
 │    └── alerts
 │
 ├── tls_protection
 ├── handshake queue
 ├── scheduled extensions
 ├── DTLS support
 └── QUIC support
```

This explains why TLS, DTLS, and QUIC can share the same session/protection foundation while keeping different wire formats.

### DTLS specialization

DTLS reuses TLS handshake semantics but adds datagram-specific state:

```text
DTLS record
 ├── epoch
 ├── record sequence
 └── fragment

DTLS handshake
 ├── message sequence
 ├── fragment offset
 └── fragment length
```

The implementation contains explicit reconstruction handling for fragmented handshake messages and keeps epoch/sequence information in session state.

### Transport-facing orchestration

The protocol objects do not themselves define the entire socket handshake loop. `tls_composer` and the trial socket classes provide the orchestration layer.

```text
trial socket
    ↓
tls_composer
    ↓
construct / send handshake records
    ↓
receive / parse peer records
    ↓
tls_session state changes
    ↓
next handshake action
```

The same composer family also has a QUIC handshake path, showing where TLS semantics meet transport-specific packet construction.

## Flow

### TLS 1.3 full handshake

```text
ClientHello
  ├── supported_versions
  ├── key_share
  ├── signature_algorithms
  └── other extensions
        ↓
ServerHello
  ├── selected version
  ├── selected cipher suite
  └── key_share
        ↓
shared secret / handshake secrets
        ↓
EncryptedExtensions
        ↓
Certificate / CertificateVerify
        ↓
Finished
        ↓
application traffic secrets
        ↓
protected application data
```

### TLS 1.3 PSK / 0-RTT

```text
ClientHello
 ├── pre_shared_key
 ├── psk_key_exchange_modes
 ├── early_data
 └── optional key_share
        ↓
resumption / early secret
        ↓
0-RTT application data
        ↓
ServerHello
        ↓
handshake traffic secrets
        ↓
Finished
        ↓
1-RTT application data
```

### TLS 1.2

```text
ClientHello
   ↓
ServerHello
   ↓
Certificate / key exchange
   ↓
ClientKeyExchange
   ↓
pre-master secret
   ↓
master secret / key block
   ↓
ChangeCipherSpec / Finished
   ↓
protected application data
```

### DTLS

```text
UDP datagrams
    ↓
DTLS record
    ↓
epoch / sequence
    ↓
handshake fragment
    ↓
reassembly
    ↓
TLS handshake processing
```

### TLS + QUIC

```text
TLS ClientHello / ServerHello / ...
              ↓
        TLS session state
              ↓
       QUIC CRYPTO frame
              ↓
          QUIC packet
              ↓
      QUIC packet protection
```

The TLS key schedule is therefore shared conceptually with QUIC, while QUIC owns packet numbering, packet protection layout, and frame transport.

## Study & Verification

### Protocol understanding

The repository contains dedicated understanding cases for TLS 1.2, TLS 1.3, and DTLS:

- `testcase_understand_tls12`
- `testcase_understand_tls13`
- `testcase_understand_dtls`

These are useful because they preserve the protocol reasoning separately from the production implementation.

### RFC 8448 executable traces

`testcase_rfc8448_2` through `testcase_rfc8448_7` reconstruct the RFC 8448 TLS 1.3 examples, covering simple 1-RTT, HelloRetryRequest, resumed 0-RTT, client authentication, and compatibility-mode paths.

### Construction tests

`testcase_construct_tls`, `testcase_construct_dtls12_1`, `testcase_construct_dtls12_2`, and `testcase_construct_dtls13` exercise construction of protocol objects rather than relying only on live sockets.

### Cryptographic tests

Representative tests include:

- `testcase_pre_master_secret`
- `testcase_tls12_aead`
- `testcase_mlkem_encoding`

The implementation also contains SSLKEYLOG import/export support, which connects derived TLS secrets to encrypted traffic analysis and replay.

### Interoperability and capture replay

The TLS test tree contains real client/server traces for:

```text
TLS 1.2
TLS 1.3
DTLS 1.2
HTTP/1.1 over TLS
HTTP/2 over TLS
TLS 1.3 ML-KEM / hybrid groups
```

The PCAP/YAML replay tests connect these captures to reproducible protocol verification.

## Status

| Area | Revision 1084 state |
|---|---|
| TLS 1.2 protocol / protection | implemented and extensively tested |
| TLS 1.3 protocol / protection | implemented and extensively tested |
| TLS handshake messages | broad implementation |
| TLS extensions | broad implementation |
| Transcript / key schedule | implemented |
| AEAD / CBC-HMAC protection | implemented and tested |
| DTLS 1.2 | implemented and tested |
| DTLS fragmentation / reconstruction | implemented and tested |
| TLS 1.3 ML-KEM / hybrid key exchange | tested |
| TLS 1.3 ML-DSA certificate path | tested |
| Real TCP/TLS interoperability | tested |
| HTTP/1.1 / HTTP/2 over TLS | tested |
| PCAP + SSLKEYLOG replay | implemented and tested |
| QUIC TLS handshake integration | substantial / ongoing |
| `tls_composer` QUIC integration | remaining integration work exists |
| `network_server` integration | active adjacent work |

The remaining items should not be read as a lack of TLS protocol implementation. Most of the TLS protocol and cryptographic foundation is already a substantial completed study/implementation area; the open work is primarily at the orchestration and transport-integration boundaries.

## Related topics

```text
                    ASN.1 / X.509
                          │
                          ▼
TCP ────────────────►  TLS  ◄────────────── KEM / PQC
                          │
                 ┌────────┴────────┐
                 │                 │
                DTLS              QUIC
                 │                 │
                UDP              HTTP/3
```

TLS therefore owns the handshake/security semantics shared with QUIC, while TCP/DTLS/QUIC own their respective transport or packet boundaries.

---

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1084            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
