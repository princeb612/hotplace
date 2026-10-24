## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# TLS protection and session model

## 1. Role

The TLS implementation separates protocol messages from the state that makes those messages secure and usable over a transport.

```text
TLS messages
    │
    ├── record / handshake / extension
    │
    ▼
protection
    │
    ├── transcript hash
    ├── key schedule
    ├── key block / traffic secrets
    ├── AEAD / CBC-HMAC
    └── header protection
    │
    ▼
session / transport integration
```

This boundary is important when reading the source: a handshake class describes a protocol message, while `tls_protection` calculates or applies the cryptographic state needed to protect that message or record.

## 2. Data Model

### Session-owned state

tls_session combines protocol lifecycle with per-direction session_info and tls_protection. The session selects TLS, DTLS, QUIC, or QUIC v2 mode; retains status/configuration and scheduled handshake/extension work; and lazily creates composer, DTLS, and QUIC helpers.

session_info tracks current handshake status, whether protection is active, queued alerts, per-protection-space record numbers, and session-specific keyed values. This is where protocol progress and sequence context are associated with direction; it is not itself the store for every cryptographic secret.

### Protection-owned state

tls_protection holds the negotiated version and cipher suite, negotiation context, key/key-exchange objects, transcript-hash state, and named secret collection. Its APIs calculate key material and Finished values, build nonce/AAD inputs, encrypt/decrypt TLS/DTLS records, and derive masks used for DTLS 1.3/QUIC header protection.

### Intermediate data and ownership boundary

| Data | Primary responsibility | Used by |
|---|---|---|
| Offered/selected cipher suite, versions, groups, signature schemes | protection_context | Negotiation and schedule setup |
| Handshake transcript/checkpoint digest | tls_protection, advanced by handshake/session path | Finished verification and staged derivation |
| TLS 1.2 master secret/key block | TLS 1.2 calculation path | Directional MAC/encryption key setup |
| TLS 1.3 traffic secrets and key/IV values | TLS 1.3 calculation path | Record protection or QUIC key derivation |
| TLS/DTLS directional record number / protection space | `session_info` | TLS/DTLS record nonce/AAD and record sequencing |
| QUIC packet-number ranges | `quic_session` | QUIC packet-number allocation/reconstruction by packet-number space |
| DTLS peer record pool / fragment descriptors | DTLS arranger/publisher | Datagram record input/output |
| QUIC pending frame layout / packet number | QUIC session, publisher and packet layer | QUIC packet construction/protection |

The boundary matters because the same session can coordinate several protocol layers, but TLS record numbers, DTLS epoch/sequence values, and QUIC packet numbers remain distinct.

## 3. Behavior Model

### Handshake-to-protection flow

The source implements this as message-specific hooks coordinated by the base handshake reader/writer, not as one central routine that handles every TLS version.

~~~text
tls_handshake::read() / write()
  -> do_preprocess()
  -> parse or serialize message fields
  -> do_postprocess()
       ├─ validate message-specific prerequisites
       ├─ update transcript at protocol-defined points
       ├─ calculate version/flow-specific key material
       └─ update aggregate session status / schedule work
  -> tls_session::run_scheduled(dir)
       └─ message-specific deferred action
~~~

1. **ClientHello establishes the initial transcript input.** Its post-processing path resets/updates transcript state and calls tls_protection::calc(...client_hello...) where the selected flow requires it. The HelloRetryRequest/retry path has distinct transcript handling; it must not be simplified to “append every ClientHello to a fresh hash.”
2. **ServerHello selects the negotiated parameters.** The message validates that ClientHello has already been observed, resolves the selected version (including supported_versions) and cipher suite into protection state, then prepares the transcript for the current flow. In the ordinary one-RTT path, it resets the transcript and adds the saved ClientHello before calculating the hash with ServerHello. The TLS 1.3 calculation path derives client/server handshake traffic secrets from the shared secret and the ClientHello…ServerHello transcript context. HRR/zero-RTT paths have separate flow and downgrade handling.
3. **Later handshake messages advance the transcript individually.** For example, EncryptedExtensions updates the transcript and sets its aggregate status bit; CertificateVerify updates the transcript and records the direction-specific certificate-verification event. The specific message hook determines the order; record parsing alone does not automatically hash all bytes.
4. **Finished is both a verification point and a schedule transition.** Its pre-processing checks prerequisites that differ by protocol version and flow. For TLS 1.2/DTLS 1.2 it also requires that protection is already active for that direction. Post-processing adds the Finished message to the transcript, invokes tls_protection::calc(...finished...), records verify data and the appropriate client/server Finished event, and schedules the message's deferred action.
5. **Deferred Finished work updates directional state.** The base handshake reader calls tls_session::run_scheduled(dir) after successful post-processing. The Finished message's run_scheduled() sets that direction's current handshake type to Finished and resets its record counter. This directional status is distinct from the aggregate status bitmask used by waiters and hooks.

### Protection activation and sequence reset

- In the TLS 1.2/DTLS 1.2 ChangeCipherSpec path, tls_record_change_cipher_spec::do_postprocess() calls session_info::begin_protection() for the record's direction and resets that direction's record number. This is an explicit directional activation point.
- Do not generalize that ChangeCipherSpec mechanism to all TLS 1.3 transitions. TLS 1.3 uses staged traffic secrets and version/flow-specific record handling; the relevant message and record paths determine which secrets are ready and when they are used.
- Record numbers, DTLS epochs/record sequence numbers, DTLS handshake sequence numbers, and QUIC packet numbers remain distinct. Finished's scheduled reset of the session record counter is not itself proof that every transport's numbering state is identical.

### Finished verification is separate from Finished post-processing

The source has a significant two-step order for an incoming Finished message:

1. `tls_handshake_finished::do_read_body()` reads the peer's `verify_data` and calls `tls_protection::calc_finished()` to compute the expected value against the transcript state that exists before the received Finished is appended.
2. The expected and received values are compared. A mismatch queues a fatal `handshake_failure`, resets aggregate session status, and returns a verification error; the message's successful post-processing path should not be treated as having completed.
3. After successful body processing, `do_postprocess()` appends the encoded Finished message to the transcript, calls `tls_protection::calc(...finished...)`, saves direction-specific verify data, records the client/server Finished event, and schedules deferred work.
4. The scheduled `run_scheduled(dir)` sets that direction's current handshake status to Finished and resets the session record counter.

The formulas selected by `calc_finished()` differ by protocol version:

- **TLS 1.3:** select the server or client handshake traffic secret by direction; derive the `finished` key with TLS/DTLS 1.3 HKDF-Expand-Label; HMAC the current transcript digest with that key. The Finished value is not calculated directly with the traffic secret as the HMAC key.
- **TLS 1.2 / DTLS 1.2:** use the master secret as the HMAC-based PRF secret, prepend the direction-specific label (`server finished` or `client finished`) to the transcript hash, and produce 12 bytes of verify data.

The write path also calls `calc_finished()` to construct the value to serialize. Therefore the same calculation routine is used for producing local Finished content and verifying peer-provided content, but the transcript checkpoint at the call site is crucial.

### From derived values to record protection

Deriving a secret and using it for a record are related but distinct source steps.

- **TLS 1.2 / DTLS 1.2:** after ClientKeyExchange, `tls_protection::calc(...client_key_exchange...)` derives or retrieves the master secret, calls `calc_keyblock()`, and stores the resulting named values. The key-block expansion uses the seed `"key expansion" || server_random || client_random`. Its output is partitioned in order into client/server MAC secrets (for CBC suites), client/server encryption keys, and client/server IVs. Non-CBC suites do not consume the MAC-secret portions.
- **TLS 1.3:** the calculation path stores named early, handshake, and application secrets and derives directional key/IV values with HKDF-Expand-Label. When server Finished is processed, the code derives client/server application traffic secrets and their keys/IVs from the application secret and the transcript checkpoint through server Finished. When client Finished is processed, it derives resumption-related material using the checkpoint through client Finished.
- **Record use:** the record protection path subsequently selects named key/IV secrets according to direction and protection space, builds the nonce and AAD, and calls the cryptographic operation. The derivation routine populating a secret collection is not, by itself, the same operation as sending a record or changing the session's directional protection flag.

### Key derivation is not key activation

The source has separate boundaries for calculating material, validating Finished, and enabling protection:

- **TLS 1.2 / DTLS 1.2:** after ClientKeyExchange, the protection calculation derives the master secret and stores the key-block outputs (CBC MAC secrets where applicable, directional encryption keys, and IVs). The later ChangeCipherSpec handler calls begin_protection() for that message's direction and resets that direction's record number. The fact that named keys exist before ChangeCipherSpec does not mean that direction is already protected.
- **TLS 1.3 / DTLS 1.3:** ServerHello processing derives handshake traffic secrets and handshake keys/IVs. The server-direction Finished post-processing path advances the transcript through server Finished and derives application traffic secrets and their keys/IVs; client-direction Finished derives resumption-related material. The exact record/session path still decides which protection state applies to each direction and phase.
- **Finished verification:** an incoming Finished body is checked against the transcript checkpoint before that Finished is added. Only after successful body processing does post-processing append Finished to the transcript, run the Finished calculation stage, record the directional Finished event, and schedule the deferred status/record-counter transition.

This is why “secret derived,” “peer Finished verified,” and “directional protection active” should be treated as three different claims when tracing a handshake. They occur in related but not interchangeable source paths.
- **QUIC use:** Initial keys derive from the QUIC version's fixed Initial salt and destination connection ID before TLS handshake traffic secrets exist. Handshake/Application keys, IVs, and header-protection keys derive from TLS 1.3 traffic secrets using QUIC-specific labels, then are selected by direction and packet-number space. These are not TLS record keys in a different framing wrapper.

### Transcript input boundary

`tls_protection::update_transcript_hash()` receives handshake bytes from message-specific code. For DTLS 1.3 it hashes the TLS-style handshake header and body while excluding the DTLS-only reconstruction fields (`message_seq`, `fragment_offset`, and `fragment_length`). This is different from DTLS 1.2's transcript/MAC rules; the implementation contains version-specific handling, so avoid describing the transcript as a raw hash of record buffers.

### From selected secret to protected record

The AEAD record path resolves key material by the session's protection context rather than by looking only at the cipher suite:

- For TLS/DTLS, get_aead_key() combines direction, negotiated TLS version, current per-direction handshake status, and flow (including early data) to choose client/server handshake or application key/IV names. TLS 1.2 instead selects the directional key-block key/IV names.
- For QUIC, the same selector uses an explicit protection space—Initial, Handshake, or Application—and QUIC-specific secret names. QUIC packet number spaces are not TLS record sequence counters.
- write_aad() builds the associated data from the version-appropriate record fields. TLS 1.2 AEAD includes sequence number plus content type/version/plaintext length; DTLS 1.2 uses epoch and record sequence. TLS 1.3 authenticates the outer record header while the encrypted inner content type remains inside the ciphertext.
- The AEAD routine combines the selected key/IV with the protocol-specific record number to construct the nonce where required, then submits nonce, AAD, plaintext/ciphertext and tag to the crypto backend. On receive, successful authentication precedes plaintext consumption.
- CBC suites follow a separate CBC-HMAC path, selecting directional encryption and MAC keys and applying MtE or EtM according to the session's negotiated/configured flag. That legacy path must not be described using AEAD's tag/nonce model.

### Record and packet protection

When a protected record or packet is processed, direction and the relevant protection-space/sequence context select the cryptographic inputs. The protection layer builds the appropriate AAD/nonce or packet-protection inputs, then authenticates/decrypts inbound bytes or encrypts outbound content. A successful primitive operation does not itself establish that the handshake is complete; the calling protocol/session path owns error handling and state progression.

### Transport-specific continuation

- **TLS:** handshake content is framed and protected as TLS records over a stream-oriented transport.
- **DTLS:** outbound handshake bodies may be fragmented into DTLS records; inbound records are validated and ordered by peer address and epoch/record sequence before the next stage consumes them.
- **QUIC:** handshake bytes travel in CRYPTO frames; application and HTTP/3/QPACK stream bytes travel in STREAM frames. Initial packet protection derives from the version-specific salt and destination connection ID; Handshake/Application packet protection uses TLS-derived secrets with QUIC packet-number spaces and packet/header protection.

SSLKEYLOG import/export is an auxiliary diagnostic path for labeled secret material. It does not replace live session state and the exported values are sensitive because they can help decrypt captured traffic.

## 4. Relationships
- `protection/tls_protection*.cpp`
- `session/tls_session.cpp`, `session/dtls_record_arrange.cpp`, `session/dtls_record_publisher.cpp`
- `session/quic_packet_publisher.cpp`, `session/quic_session.cpp`, `session/quic_streams.cpp`
- `session/sslkeylog_exporter.cpp`, `session/sslkeylog_importer.cpp`
- [TLS protection overview](protection/README.md)
- [TLS session overview](session/README.md)
- [TLS/DTLS/QUIC overview](README.md)
- [TLS message model](tls-message-model.md)
- [TLS advisor](advisor/README.md)
- [QUIC/TLS integration](quic-tls-integration.md)

### Related areas

- `../basic/` — socket and OpenSSL transport adapters
- `../session/` — stateful TLS/DTLS/QUIC processing
- `../quic/` — QUIC packet/frame implementation
- `sdk/crypto/` — underlying HKDF, HMAC, AEAD and signature/key operations

## 5. References
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
