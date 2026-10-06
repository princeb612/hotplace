# Hotplace TLS → DTLS → QUIC Development Path

## Source Baseline

- Source revision: 1097
- Review question: how does the wire representation change as the study moves from TLS records to DTLS datagrams and then to QUIC packets?

## 1. Perspective

In hotplace, TLS, DTLS, and QUIC are better understood as one long study and implementation path than as three completely independent protocol implementations.

The approximate progression is:

```text
TLS study
   ↓
xargs.org / test vectors
   ↓
key schedule / handshake understanding
   ↓
self-written crypto implementation
   ↓
record / handshake / extension
   ↓
CBC-HMAC / EtM roadblock
   ↓
crypto / protocol details reinforced
   ↓
DTLS
   ↓
QUIC
```

The purpose of this document is not to provide a general introduction to TLS.

It is to reconstruct **what hotplace learned while studying TLS, and which problems from that process led naturally to the next protocol**.

---

## 2. Starting Point: TLS Cannot Be Understood as Protocol Fields Alone

Implementing TLS requires more than reading the RFC text.

It is necessary to understand how the following pieces are connected:

```text
handshake
  ↓
transcript
  ↓
key schedule
  ↓
traffic secrets
  ↓
record protection
```

The hotplace TLS implementation process was therefore less about adding protocol fields one by one and more about understanding cryptographic calculations and the wire protocol at the same time.

---

## 3. xargs.org and Test Vectors

TLS-related material from xargs.org and test vectors became an important turning point in this process.

When implementation is based only on RFC text, it is easy to end up with a one-way flow:

```text
official specification
   ↓
my understanding of the algorithm
   ↓
my implementation
```

Test vectors make a stronger validation loop possible:

```text
known input
   ↓
known intermediate value
   ↓
known output
   ↓
my implementation
```

For areas with many intermediate stages, such as the key schedule, comparing the value at each stage is much stronger than checking only whether the final handshake succeeds.

---

## 4. What Changed After Understanding the Key Schedule

A major turning point in the TLS implementation was being able to follow the key schedule using actual values.

Conceptually:

```text
PSK / ECDHE
      ↓
handshake secret
      ↓
traffic secret
      ↓
key / IV
      ↓
record protection
```

Once the intermediate values can be inspected, the question changes from merely asking whether TLS works to asking **why a particular result is produced**.

That experience directly influenced later crypto implementation work.

---

## 5. What It Means to Implement Crypto Directly

In hotplace, implementing required cryptographic primitives directly progressed together with the TLS study.

The significance is not simply replacing OpenSSL.

For example, the complete path can be examined directly:

```text
TLS specification
      ↓
required primitive
      ↓
crypto implementation
      ↓
test vector
      ↓
TLS integration
```

This makes it possible to distinguish a protocol error from an error in the underlying cryptographic primitive.

---

## 6. TLS Record / Handshake / Extension

Once the cryptographic calculations were understood, the structure of the actual TLS wire protocol became more important.

Roughly:

```text
TLS connection
      │
      ├── handshake
      │     ├── ClientHello
      │     ├── ServerHello
      │     └── ...
      │
      ├── extensions
      │
      └── record layer
```

As the study later moved toward QUIC, the TLS handshake acquired significance beyond ordinary TLS record exchange.

Hotplace therefore came to treat handshake, extensions, and record protection as connected parts of one structure rather than isolated topics.

---

## 7. A Major Roadblock: CBC-HMAC / EtM

One of the particularly difficult parts of the TLS implementation was CBC-HMAC record protection.

It is easy to begin with a simplified model such as:

```text
encrypt
+
MAC
```

but the actual protocol connects several details:

- MAC input
- sequence number
- padding
- block alignment
- encryption order
- the difference between Encrypt-then-MAC and MAC-then-Encrypt

This required separate investigation and experimentation and became substantial enough to be recorded in material such as `cbc-hmac-survey.md`.

---

## 8. Why CBC-HMAC Matters

This experience was not merely an exercise in implementing one older cipher mode.

It demonstrated that a real protocol requires the following to match exactly:

```text
cryptographic primitive
        +
protocol-specific construction
        +
wire representation
```

In other words:

```text
AES is correct
SHA is correct
HMAC is correct
```

is not enough to prove that a TLS record implementation is correct.

The primitives must be combined using the exact inputs and ordering defined by the protocol.

This became an important foundation for understanding AEAD and packet protection in QUIC later.

---

## 9. From TLS to DTLS

Once TLS was understood to a sufficient degree, moving to DTLS did not discard the existing concepts. Instead, those concepts had to be adapted to a different transport model.

Conceptually:

```text
TLS
 └─ reliable ordered transport
        ↓
DTLS
 └─ datagram transport
```

The basic ideas of handshake and record protection remain, but datagram transport introduces additional concerns:

```text
packet loss
reordering
retransmission
message fragmentation
```

The study therefore changes from simply understanding TLS to asking what changes when the same security concepts are applied to a datagram transport model.

---

## 10. The Significance of DTLS

In hotplace, DTLS is better viewed as a step that broadens the network protocol abstraction than as a simple variation of TLS.

```text
TLS
  ↓
security protocol concepts
  ↓
DTLS
  ↓
datagram-oriented security
```

This makes the relationships among records, handshakes, sequence numbers, retransmission, and fragmentation more visible.

That experience naturally connects to the later study of QUIC.

---

## 11. DTLS Is Not Merely TLS over UDP

The DTLS step is valuable because it exposes responsibilities that do not exist in the same form in the reliable TLS stream model.

```text
TLS stream
   │
   ├── record
   └── handshake
          │
          ▼
DTLS datagram model
   │
   ├── record sequence
   ├── epoch
   ├── retransmission
   └── handshake fragmentation
```

This changes the learning question. Instead of only asking how a record is encoded, the implementation must also ask how records are ordered, reconstructed, fragmented, and published when the transport no longer guarantees a reliable ordered byte stream.

That distinction appears clearly in the send/receive directions:

```text
receive
datagram
   ↓
dtls_record_arrange
   ↓
ordered / reconstructed records
   ↓
TLS processing

send
TLS handshake record
   ↓
dtls_record_publisher
   ↓
fragmented / segmented DTLS records
   ↓
datagram
```

The two components therefore provide a useful study pair: **receive-side reconstruction versus send-side construction**. The important lesson is not the individual API, but the additional responsibilities introduced by the datagram model.

---

## 12. Moving Toward QUIC

QUIC couples TLS and transport protocol semantics much more tightly.

From a traditional perspective, it is common to imagine a stack such as:

```text
application
   ↓
TLS
   ↓
TCP
   ↓
IP
```

QUIC is closer to:

```text
application
     ↓
QUIC
 ┌───┴───────────────┐
 │                   │
transport        TLS 1.3
semantics        handshake
 │                   │
 └──── packet protection
            ↓
           UDP
```

Security handshake and transport therefore become closely coupled.

The knowledge gained from TLS becomes a direct foundation for QUIC implementation.

---

## 13. The TLS Handshake Reappears in QUIC

QUIC does not discard the TLS handshake.

Instead, it uses the TLS 1.3 handshake and connects its results to QUIC connection establishment and packet protection.

Conceptually:

```text
TLS handshake
      ↓
traffic secrets
      ↓
QUIC packet protection
      ↓
protected QUIC packets
```

Implementing QUIC therefore requires more than knowing that a TLS handshake exists. It requires understanding how the key schedule and traffic keys connect to actual packet protection.

---

## 14. What Changes in QUIC

Moving to QUIC introduces new transport concerns in addition to TLS:

```text
QUIC
 ├── packet
 ├── frame
 ├── connection ID
 ├── variable-length integer
 ├── ACK range
 ├── loss / recovery
 └── stream
```

The cryptographic and security knowledge gained from TLS is now combined with new transport machinery.

This is where several previously documented hotplace abstractions meet again:

```text
payload
   ↓
QUIC packet/frame layout

range_set
   ↓
ACK range representation

network_session
   ↓
connection/session abstraction

binary_stream
   ↓
binary construction helpers
```

QUIC is therefore a point where several hotplace subsystems meet in a concrete protocol implementation.

---

## 15. QUIC Changes the Wire Representation Again

QUIC keeps TLS 1.3 as its handshake and security machinery, but it does not carry the TLS handshake as ordinary TLS records. The handshake bytes are carried in QUIC CRYPTO frames and assembled into protected QUIC packets together with other transport or application frames.

```text
TLS handshake
      │
      ▼
   CRYPTO frame
      │
      ├── STREAM frame  ← application data
      ├── ACK           ← transport state
      └── PADDING       ← packet construction
             │
             ▼
     quic_packet_publisher
             │
             ▼
        QUIC packet
```

This is an important continuation of the study path. TLS knowledge is retained, but its wire representation is no longer the TLS record layer. QUIC becomes the packet boundary that carries TLS handshake material and transport/application frames together.

The learning progression can therefore be summarized as:

```text
TLS
  ↓
TLS record
  ↓
DTLS record / datagram
  ↓
QUIC CRYPTO / STREAM / ACK / PADDING frames
  ↓
QUIC packet
```

---

## 16. The TLS → DTLS → QUIC Study Structure

The complete progression can be viewed as:

```text
TLS
 │
 ├─ handshake
 ├─ key schedule
 ├─ record protection
 ├─ extensions
 └─ crypto primitives
 │
 ▼
DTLS
 │
 ├─ datagram transport
 ├─ retransmission
 ├─ reordering
 └─ fragmentation
 │
 ▼
QUIC
 │
 ├─ TLS 1.3 handshake
 ├─ packet protection
 ├─ ACK / recovery
 ├─ variable-length encoding
 ├─ streams
 └─ transport state
```

The later protocol does not discard the earlier study. It applies the knowledge gained in the previous stage to a more complex environment.

---

## 17. A Recurring Development Pattern

A recurring pattern in this work is:

```text
RFC / specification
        ↓
small implementation
        ↓
test vector / packet capture
        ↓
unexpected result
        ↓
debug / study
        ↓
implementation correction
```

For protocols such as TLS, where many intermediate states matter, test vectors and debug logs are particularly important validation tools.

For that reason, protocol implementations are not the only meaningful artifacts in hotplace. Experimental records, packet captures, and debugging material also preserve part of the development history.

---

## 18. Relationship with OpenSSL

During TLS/DTLS/QUIC study, OpenSSL serves both as a reference and as a comparison target.

Conceptually:

```text
hotplace implementation
        │
        ├── packet capture
        ├── key/log comparison
        └── behavior comparison
                 │
                 ▼
             OpenSSL
```

The important point is not to treat OpenSSL only as a dependency. It can also provide a practical reference for checking whether the implementation matches the RFC and observed TLS behavior.

Together with the later `trial` server/client work, this can be viewed as part of a separate verification architecture.

---

## 19. Resulting Expansion into QUIC

When QUIC is implemented, the study that began with TLS expands into the wider network architecture.

```text
crypto
  ↓
TLS
  ↓
DTLS
  ↓
QUIC
  ↓
HTTP/3 / QPACK etc.
```

Other hotplace abstractions grow alongside this process:

```text
crypto advisor / dictionary
        ↓
crypto identifiers

payload
        ↓
binary protocol layout

range_set
        ↓
ACK ranges

network_session
        ↓
connection abstraction

parser
        ↓
protocol grammar / frame parsing
```

QUIC can therefore be viewed not simply as another protocol implementation, but as a stage where several results of hotplace's earlier studies are applied together to a real protocol.

---

## 20. What This Document Should and Should Not Preserve

This document is not a complete specification reference for TLS, DTLS, or QUIC.

Detailed RFC-level protocol descriptions belong in separate RFC/study documents. The purpose here is to preserve:

1. the order in which the study progressed;
2. where implementation problems appeared;
3. which experiences led to the next protocol; and
4. where other hotplace subsystems joined the path.

In other words, this is closer to a **development/study path document than to a technical reference**.

---

## 21. Related Documents and Implementations

Related material can be grouped along the following axes.

### TLS

- TLS handshake
- TLS record
- TLS extensions
- key schedule
- cipher / digest / AEAD
- `cbc-hmac-survey.md`

### DTLS

- DTLS handshake
- datagram record
- retransmission / fragmentation
- DTLS-specific state

### QUIC

- QUIC packet
- frame
- ACK / recovery
- stream
- variable-length integer
- TLS 1.3 integration

### Supporting Components

- `sdk/crypto`
- `sdk/net`
- `sdk/io/basic/payload`
- `sdk/base/nostd/range_set`
- `sdk/net/network_session`
- parser / binary-construction components

---

## 22. Current Status

The current TLS → DTLS → QUIC path in hotplace is better understood as the result of repeatedly studying and implementing the protocols and using each stage to strengthen understanding of the others, rather than as one finished "protocol stack product".

The core path is:

```text
TLS
  ↓
key schedule / crypto understanding
  ↓
record / handshake / extensions
  ↓
CBC-HMAC / EtM investigation
  ↓
DTLS
  ↓
QUIC
  ↓
transport + TLS integration
```

Throughout this process, test vectors, packet captures, debug logs, and OpenSSL comparisons have served as important validation methods.

---

## 23. In One Sentence

Hotplace's TLS → DTLS → QUIC development path can be summarized as:

> **A study and implementation path that first established a concrete understanding of TLS cryptographic handshakes, then extended that experience to datagram security and finally to QUIC transport and TLS integration.**

Preserving this path is more valuable for reconstructing hotplace's development history than simply listing the individual features of each protocol.
