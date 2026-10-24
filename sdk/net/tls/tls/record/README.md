## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1107                  │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS record

## 1. Role

The record layer represents TLS record framing and content. It connects serialized protocol content to the session's directional protection state, but it is not the handshake state machine and does not define the meaning of a handshake message's fields.

The record abstraction is specific to TLS/DTLS framing. QUIC does not carry TLS handshake bytes inside ordinary TLS records; QUIC carries those bytes in CRYPTO frames and applies packet protection to QUIC packets.

## 2. Data Model

A `tls_record` retains its content type, session association, body size, header range, flags, and DTLS-specific epoch/record-sequence state. Its public interface provides `read()` and `write()`, as well as helpers to add nested records or handshake objects. The concrete record type determines how its body is interpreted and whether protection applies.

```text
tls_record
  ├─ content type / protocol version / declared length
  ├─ session and direction context
  ├─ record body / nested content
  │    ├─ handshake
  │    ├─ alert / other content
  │    └─ protected TLS 1.3 content
  └─ DTLS epoch + record sequence (where applicable)
```

Important distinctions:

- **Record header/body:** record-level framing and fragment bytes; not the same as the handshake header/body nested inside handshake content.
- **Session association:** record parsing/writing uses the associated session and direction to select protocol context.
- **DTLS epoch and sequence:** DTLS record sequencing is held separately from TLS stream records and QUIC packet numbers.
- **Protection decision:** the record path exposes `apply_protection()` and pre/post-processing hooks; actual behavior depends on concrete record type and protocol/session state.

## 3. Behavior Model

### Quick map: record framing and protection

```text
RECEIVE
input bytes -> parse record header -> wait/check declared body length
                                      |
                                      v
                              record body bytes
                                      |
                          protection active for direction?
                              /               \
                            yes                no
                             |                 |
                      decrypt / verify       plain body
                             \                 /
                              v               v
                         content type dispatch
                     handshake / alert / application

SEND
content object -> serialize body -> apply protection when required
                                      |
                                      v
                           construct record header
                                      |
                                      v
                              output byte range

TLS 1.3: encrypted inner content ends with the real content-type byte.
QUIC: no TLS record wrapper; handshake bytes use CRYPTO frames.
```


### Record framing and protected-content dispatch

The base record path has explicit framing and rollback boundaries:

- read() parses the record header first, checks that the declared body is present, and rejects a record length above the implementation's 16 KiB + 2048 bound with a fatal record_overflow alert. Incomplete header/body handling is distinct: an unavailable header returns no_more, while a declared body that is not fully present is treated as bad_data by this path.
- write() serializes the body before the header. If a later step fails, it restores the caller's output buffer to its original size. On DTLS output, the record snapshots the current epoch/sequence unless the record flags explicitly suppress automatic sequence control.
- do_write_header() encrypts only when both the record type's apply_protection() and the direction's session_info protection flag are true. It creates AAD, invokes the protection operation, appends the authentication tag where appropriate, then writes the record header around the protected bytes.
- do_postprocess() runs scheduled handshake actions after record construction; DTLS record sequencing is then advanced separately. This ordering matters when a Finished message changes the protection phase or resets a counter.

### TLS 1.3 inner content type

TLS 1.3's encrypted record is represented through the application_data record class at the outer record layer. Its plaintext carries the content bytes followed by an inner content-type byte. After successful decryption, the reader uses that trailing byte to dispatch the plaintext as alert, handshake, or application data. The outer record content type is therefore not the original inner content type.

The handshake-record path has its own TLS 1.3 preprocessing behavior: it resets the direction's protection state before handling handshake records, and its read path decrypts when that direction is protected. This allows the record/session path to coordinate handshake-phase protection rather than assuming that every handshake record has the same protection status.

### Receive path

1. The caller passes available bytes, direction, and a mutable position to the record reader.
2. The record parser reads its header and uses the declared record length to determine the body range. A caller must preserve incomplete input until enough bytes are available; one TCP read is not guaranteed to contain exactly one record.
3. The selected record type reads the body. Where protection applies, the record/protection path uses the session's directional cryptographic state and record sequencing context.
4. The resulting content is dispatched according to its type. Handshake content is interpreted by the handshake-message layer; alert and application-data content retain their own semantics.
5. Session state and handshake sequencing are updated by the surrounding protocol path, not inferred solely from the successful creation of a record object.

### Send path

1. The caller creates a record for the intended content type and attaches handshake/content objects or content bytes.
2. Nested content is serialized to form the record body.
3. The record writer constructs the header from the resulting body and protocol context. The protection decision is applied through the record/protection path where required.
4. The serialized record is returned to the caller's output container or callback; socket transmission is outside this class's framing operation.

### Transport-specific boundary

- **TLS over TCP:** parse a stream of records, retaining partial records and allowing multiple records in one input buffer.
- **DTLS over datagrams:** record headers include DTLS-specific sequencing context; datagram boundaries, epoch and sequence handling are not TCP stream semantics.
- **QUIC:** TLS handshake messages bypass this record framing and enter the QUIC CRYPTO-frame/packet path.

### Real-code example: separate record protection from handshake negotiation

`test/testcase/tls/testcase_tls12_aead.cpp` exercises the record-protection boundary with a captured TLS 1.2 record: it configures the cipher suite and key block, then attempts to decrypt the record and checks the result. The TLS server applet (`test/applet/tlsserver/run_server.cpp`) is the complementary integration example, where the session/backend invokes record processing below the application callback.

```text
focused testcase: fixed secret/randoms -> key block -> record decrypt/check
live server:      socket/session -> handshake state -> record protection -> application bytes
```

Use the testcase to reason about record inputs and cryptographic outputs; use the applet to reason about where records sit in the connection lifecycle. They answer different questions.

## 5. Relationships
- Parent module: [TLS implementation](../../README.md).
- [Handshake messages](../handshake/README.md) — structured handshake content inside records.
- [Extensions](../extension/README.md) — extension data nested in handshake messages.
- [TLS protection](../../protection/README.md) — cryptographic state and protected record processing.
- [TLS session support](../../session/README.md) — directional state and protocol coordination.
- [DTLS record publisher](../../dtls_record_publisher.md) — datagram-specific record publication.
- [QUIC integration](../../quic/README.md) — CRYPTO frames and packet protection instead of ordinary TLS record framing.

## 6. References
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 6347 — DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147)
