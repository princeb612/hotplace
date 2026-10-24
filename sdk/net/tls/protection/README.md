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

# TLS protection

## 1. Role

`sdk/net/tls/protection` implements TLS/DTLS cryptographic protection and key-schedule operations: transcript hashing, Finished verification inputs, key-block/PSK calculations, and record encryption/decryption. Its behavior spans the handshake and record lifecycle; it is not owned conceptually by a single record object.

## 2. Data Model

### Negotiation context versus cryptographic state

`protection_context` stores negotiation inputs and results: offered cipher suites, signature algorithms, supported groups and versions, EC point formats, key-share groups, and the selected cipher suite/version/group. It provides the context used during negotiation; it is not the repository for all derived traffic keys.

`tls_protection` is the cryptographic state boundary associated with `tls_session`. It retains the selected cipher suite and version, key/key-exchange objects, transcript-hash object, named TLS secrets, flow/key-exchange mode, and negotiation context. The session's handshake path orchestrates these operations and owns directional activation state; the protection object retains the cryptographic material and calculation helpers.

## 3. Behavior Model

### Value flow and key consumers

| Value | Producer / entry point | Consumer |
|---|---|---|
| Cipher-suite hint | `tls_advisor::hintof_cipher_suite` | Suite hash and parameter selection |
| Primitive hint/backend method | `crypto_advisor` metadata and backend lookup | Hash, HMAC, cipher, and key operations |
| Transcript digest/checkpoint | Handshake bytes passed to `tls_protection` | Finished verification and TLS 1.3 derivation |
| TLS 1.2 pre-master/master secret | Key-exchange and PRF calculation | Master-secret derivation and key-block calculation |
| TLS 1.2 key block | `calc_keyblock` | Directional MAC keys, encryption keys, and IVs as required by the suite |
| TLS 1.3 staged secrets | HKDF-based calculation | Handshake/application traffic keys and IVs |
| Direction + protection space + sequence context | `tls_session::session_info` for TLS/DTLS; QUIC session/packet state for QUIC | Directional key-context selection |
| AAD, nonce/IV, plaintext/ciphertext/tag | Record-protection path | Record authentication/encryption or verification/decryption |
| QUIC packet-protection material | TLS 1.3 secrets plus QUIC-specific labels (except Initial) | QUIC packet AEAD and header protection |

The metadata and execution layers are separate. A TLS suite hint describes protocol mapping; `crypto_advisor` resolves primitive metadata and may separately resolve a usable backend method. Metadata lookup alone neither negotiates a session nor installs traffic keys.

TLS 1.2 uses the legacy PRF, master-secret/key-block, and suite-specific record-protection paths. TLS 1.3 derives staged secrets through HKDF. QUIC Initial keys instead use the QUIC version's fixed Initial salt and destination connection ID; Handshake and Application packet keys derive from TLS 1.3 traffic secrets using QUIC-specific labels. QUIC packet protection consumes these values without using TLS record framing or counters.


### Negotiation, transcript, and key schedule

~~~text
handshake offers / selected parameters
  -> tls_protection::negotiate / protection_context
  -> selected cipher suite + version
  -> tls_advisor suite hint
  -> crypto_advisor primitive metadata / backend resolution
  -> transcript hash selected from suite hash
  -> protocol-specific calculation path
       ├─ TLS 1.2: pre-master -> master secret -> key block
       └─ TLS 1.3: staged HKDF secrets -> traffic secrets -> keys/IVs
  -> Finished verification / directional protection activation
~~~

1. **Resolve the negotiated suite.** Protection setup asks `tls_advisor` for the cipher-suite record and related TLS parameters. The suite metadata describes the hash and cipher mapping; it is not an instantiated cryptographic primitive.
2. **Resolve primitive metadata and backend capability.** The protection calculation path uses `crypto_advisor` to resolve digest/cipher metadata and, where needed, the corresponding backend method. A descriptive hint can exist even when the current OpenSSL build/provider cannot supply an executable method, so the code must treat those results separately.
3. **Initialize transcript hashing.** The transcript-hash object is created lazily from the hash associated with the selected cipher suite. Handshake processing decides when bytes are added and when a digest/checkpoint is requested. Record headers and arbitrary transport bytes are not a substitute for protocol-defined transcript input.
4. **Calculate the applicable schedule.**
   - **TLS 1.2:** the calculation path derives the master secret from the applicable pre-master secret and randoms, then `calc_keyblock` expands it using the suite's PRF/hash and partitions the result into the required directional record-protection values.
   - **TLS 1.3:** the calculation path derives staged early/handshake/application secrets and uses transcript digests at protocol-defined stages. Finished keys/verify data are calculated from the relevant secret and transcript digest.
   - **QUIC:** QUIC-specific key/IV/header-protection material is derived from TLS 1.3 secrets using QUIC labels; the result is consumed by QUIC packet protection, not TLS record protection.
5. **Apply protection only when the handshake path activates it.** The record encryption/decryption routines construct the nonce/IV and AAD appropriate to the record and selected suite, then encrypt/authenticate or verify/decrypt. The session's directional protection flag and record-number state are managed by session/handshake logic; the primitive does not independently advance the handshake.
6. **Propagate errors at the caller boundary.** A missing hint, unavailable backend, invalid key material, failed authentication, or invalid transcript input can stop a later stage. A successful low-level operation is not by itself evidence that the handshake has reached its terminal state.

### Finished calculation, key-block storage, and activation boundaries

tls_handshake_finished uses tls_protection::calc_finished() for both the locally written Finished body and the peer's received verify_data. These are different call sites over a shared calculation routine:

1. On read, do_read_body() obtains the received verify_data and calculates the expected value against the transcript state that exists before the incoming Finished message is appended.
2. A missing/empty result or unequal value queues a fatal handshake_failure, resets aggregate session status, and returns verification_failure. Successful body verification is the prerequisite for the normal post-processing path.
3. On successful post-processing, do_postprocess() appends the encoded Finished handshake message to the transcript, invokes tls_protection::calc(...finished...), saves the direction-specific verify_data, records the client/server Finished event, and schedules deferred state work.
4. On write, do_write_body() invokes the same calc_finished() routine to produce the serialized verify_data. The caller's transcript checkpoint—not a different formula in the read and write routines—determines which handshake bytes are authenticated.

calc_finished() selects two distinct constructions:

- **TLS 1.3 / DTLS 1.3:** choose c_hs_traffic or s_hs_traffic according to direction, derive a dedicated finished key with the TLS/DTLS 1.3 HKDF-Expand-Label operation, then HMAC the current transcript digest. The traffic secret itself is not directly used as the Finished HMAC key.
- **TLS 1.2 / DTLS 1.2:** use master as the PRF/HMAC secret, combine the direction-specific label (client finished or server finished) with the transcript hash, and produce 12 bytes of verify_data.

The calculation routines and activation transitions should not be collapsed into a single “keys become active” step:

- **TLS 1.2 / DTLS 1.2:** calc(...client_key_exchange...) derives the master secret (unless supplied through the configured secret-import path), then calls calc_keyblock(). The key block is expanded from master_secret using key expansion || server_random || client_random. For CBC suites, the output begins with client/server MAC secrets; it is then partitioned into client/server encryption keys and IVs. For non-CBC suites, the MAC-secret portions are omitted. These values are stored in the named secret collection; the directional session protection flag is activated separately by the corresponding ChangeCipherSpec path.
- **TLS 1.3 / DTLS 1.3:** calc(...server_hello...) derives handshake traffic secrets and their directional key/IV values. The calc(...finished...) branch for a server-direction Finished uses the transcript checkpoint through server Finished to derive client/server application traffic secrets, application keys/IVs, and the exporter master secret. The client-direction Finished branch derives resumption master/resumption material from the checkpoint through client Finished. In DTLS, the path also derives the relevant sequence-number-protection keys.
- **QUIC Initial:** before TLS handshake traffic secrets exist, the QUIC calculation path derives the Initial secret from the version-specific fixed salt and the stored destination connection ID, then derives client/server Initial secrets and QUIC-labelled key, IV, and header-protection values. QUIC v1 and v2 use different Initial salts and label sets.
- **QUIC Handshake/Application:** later TLS 1.3 stages derive QUIC-labelled key, IV, and header-protection values from the corresponding TLS handshake/application traffic secrets. The QUIC packet path consumes them by direction and packet-number space. None of these steps activates TLS record protection or turns QUIC packet numbers into TLS record numbers.

Thus, *derivation* means calculating and storing named secret/key material; *verification* means checking the peer's Finished value against the pre-message transcript checkpoint; and *activation/use* is controlled by the version-specific handshake, session, record, or packet path.

### Quick map: derivation is not activation

```text
Negotiated version + cipher suite
              |
        transcript hash
              |
       +------+------------------+
       |                         |
   TLS / DTLS 1.2            TLS / DTLS 1.3
       |                         |
 pre-master secret          staged HKDF secrets
       |                         |
 master secret              handshake traffic secrets
       |                         |
 key block                  handshake keys / IVs
       |                         |
 stored MAC/key/IV values   Finished verification
       |                         |
 ChangeCipherSpec           server Finished checkpoint
 activates direction         derives application secrets
                                 |
                         direction/phase key selection

QUIC Initial: version salt + destination connection ID
QUIC Handshake/Application: TLS traffic secret + QUIC labels
```

The diagram separates *material becoming available* from *the session path selecting and using it*. TLS 1.2's key block is stored before the corresponding ChangeCipherSpec activation; TLS 1.3 follows its staged handshake/application-secret flow. QUIC Initial is derived independently of TLS handshake traffic secrets.

### Record protection flow at a glance

```text
SEND
plaintext + direction + protection space + record number
                         |
                         v
              select directional key / IV
                         |
             +-----------+-----------+
             |                       |
          TLS 1.2                  TLS 1.3
       suite-specific           encoded outer header
       nonce + AAD              as AEAD AAD
             |                       |
             +-----------+-----------+
                         |
                  AEAD encrypt
                         |
                  ciphertext + tag
                         |
RECEIVE                  v
record header -> choose key / nonce / AAD -> AEAD verify + decrypt
                                                    |
                                         +----------+----------+
                                         |                     |
                                      success                failure
                                         |                     |
                                  authenticated bytes     fatal alert/error
```

This is the common outline, not one universal wire construction: TLS 1.2 GCM/CCM carries an explicit nonce; TLS 1.3 authenticates its encoded outer record header; CBC-HMAC follows the separate MAC/padding path described below.

### Record protection: key selection, nonce, AAD, and authentication

The record-protection path has four independent inputs: direction, protection space, per-direction sequence state, and the negotiated cipher construction. It does not select a key from the record header alone.

1. **Select the named key and IV.** `get_aead_key()` uses session type and direction. For TLS/DTLS 1.2 it selects `client_key/client_iv` or `server_key/server_iv`; for TLS/DTLS 1.3 it also checks the directional handshake status and flow to choose early-traffic, handshake, or application key/IV values. QUIC instead uses the explicit Initial, Handshake, or Application protection space to select QUIC-specific key/IV names. Initial protection uses the fixed AES-128-GCM/SHA-256 suite mapping (`0x1301`) in the AEAD path; this does not mean Initial keys are negotiated TLS traffic keys.

2. **Build the AAD for the protocol version.**
   - **TLS 1.2 / DTLS 1.2 AEAD:** the authenticated structure is the 64-bit TLS record sequence, or DTLS epoch concatenated with its 48-bit record sequence, followed by content type, legacy record version, and plaintext length. On receive, `build_tls12_aad_from_record()` reads those fields from the received record header and subtracts the explicit nonce and tag lengths from the encoded record length before constructing the AAD.
   - **TLS 1.3 / DTLS 1.3 record AEAD:** the encoded outer record header is passed as AAD. Its length describes the encrypted record content, including the authentication tag. The inner content type is encrypted inside the TLSInnerPlaintext and is not the outer header's content type.
   - **CBC-HMAC:** this is a separate path, not an AEAD AAD/tag construction. It creates the MAC input from the sequence domain, content type, version, and plaintext length, with additional handling for Encrypt-then-MAC.

3. **Construct the nonce according to the suite.**
   - **TLS/DTLS 1.3 and TLS/DTLS 1.2 ChaCha20-Poly1305:** `build_iv()` copies the 12-byte static IV and XORs the record number into its low eight bytes. For DTLS 1.2 ChaCha20-Poly1305, the record number is formed from epoch plus record sequence. This is not the TLS 1.2 GCM explicit-nonce format.
   - **TLS/DTLS 1.2 GCM and CCM:** the fixed IV/salt is combined with an 8-byte explicit nonce. The write path creates and stores that explicit value in the secret collection and prepends it to the encrypted fragment; the read path takes those eight bytes from the fragment and combines them with the fixed IV. The AAD length is calculated without the explicit nonce and authentication tag.
   - The helper assumes the protocol's 12-byte nonce layout when applying the XOR rule; do not generalize that helper to arbitrary IV lengths or to every cipher mode.

4. **Invoke the cryptographic backend.** `encrypt_aead()` / `decrypt_aead()` resolve cipher parameters, retrieve the selected key and IV, assemble nonce and AAD, and pass the data and tag to the crypto backend. On receive, a failed authentication/decryption queues a fatal `decryption_failed` alert and the caller must not treat the output as authenticated plaintext. The sequence state is obtained from the session for the selected protection space; it is not interchangeable with DTLS handshake message sequence or QUIC packet numbers.

The legacy CBC path is implemented separately in `tls_protection_encryption_cbchmac.cpp`:

- `get_cbc_hmac_key()` selects the directional encryption key and MAC key. The authentication input includes the record-number domain and record metadata; DTLS combines epoch and record sequence for the record MAC context.
- **MAC-then-Encrypt (MtE):** the MAC is calculated over the plaintext record content before CBC encryption. CBC padding and the explicit IV are part of the encrypted-record construction.
- **Encrypt-then-MAC (EtM):** ciphertext is authenticated after encryption, and the IV/ciphertext/tag layout and validation order differ from MtE. The negotiated/configured EtM state selects this construction.
- The CBC implementation has its own padding, MAC verification, and failure handling. It must not be described as an AEAD operation with a nonce and authentication tag, even though both constructions ultimately provide integrity checks.

### Header protection is not record AEAD

`tls_protection_hp.cpp` provides the distinct header-protection operations used for DTLS 1.3 ciphertext headers and QUIC packets. Header protection masks selected header bits using a sample and a header-protection key; it does not replace packet/record AEAD and does not authenticate the header on its own. In QUIC, the packet path must first identify the protected packet layout and sample, remove header protection, recover the packet number, and then perform packet AEAD with the appropriate packet-number space. DTLS 1.3 has its own unified-header/ciphertext-header handling. Neither operation should be merged into the TLS record nonce/AAD description.

### Transcript handling and protocol-specific input

The transcript hash is a running cryptographic state, not a hash of every received packet. The implementation updates it with handshake representations supplied by the handshake/session path. In DTLS 1.3, the implementation specifically hashes the TLS-style handshake header and body while omitting DTLS message-sequence and fragmentation reconstruction fields. Other DTLS/TLS paths follow their own protocol-defined message representation. HelloRetryRequest and Finished require stage-specific transcript treatment, so their handling must be read with the calculation/handshake call sites.

### Distinct protection domains

- **TLS record:** directional record sequence, record header/AAD, nonce/IV, and negotiated record keys.
- **DTLS record:** DTLS epoch/record sequence and DTLS-specific record/handshake representation.
- **QUIC packet:** Initial protection is rooted in the destination connection ID and version-specific Initial salt; Handshake/Application protection is rooted in TLS traffic secrets. Packet-number space, packet header, header-protection sample, and packet AEAD inputs are QUIC-specific.

The session can coordinate all three families, but they do not share one counter or wire format.

### Real-code example: derive and verify record-protection inputs

`test/testcase/tls/testcase_tls12_aead.cpp` is a focused caller of the protection model. It selects TLS 1.2 and cipher suite `0xc02b`, supplies fixed client/server randoms and a master secret to `calc_keyblock`, checks expected client key/IV values, and then attempts record decryption against captured bytes.

```text
fixed TLS 1.2 inputs -> calc_keyblock(...)
  -> directional secrets / keys / IVs
  -> compare expected values
  -> decrypt captured record
```

This testcase isolates key derivation and record protection. It does not execute a complete handshake, validate a certificate, or establish interoperability with a live peer; use `test/applet/tlsserver/run_server.cpp` for the separate end-to-end socket path.

## 5. Relationships
- [TLS key schedule](tls_key_schedule.md) — TLS 1.2 key block and TLS 1.3 staged derivation.
- [Transcript hash](tls_transcript_hash.md) — transcript input and stage checkpoints.
- [MtE vs EtM](tls_mte_etm.md) — legacy CBC authentication order and AEAD distinction.
- `tls_protection_calc.cpp`, `tls_protection_calc_finished.cpp`, `tls_protection_calc_keyblock.cpp`, `tls_protection_calc_psk.cpp`.
- `tls_protection_context.cpp`, `tls_protection_encryption_aead.cpp`, `tls_protection_encryption_cbchmac.cpp`, `tls_protection_hash.cpp`, `tls_protection_hp.cpp`.
- `sdk/crypto/basic/kdf/`, `digest/`, `crypt/`, and `mac/` — lower-level derivation and cryptographic primitives.
- [TLS session support](../session/README.md) — decides handshake stage and state transition.
- [TLS protection/session flow](../tls-protection-and-session.md) — message-specific transcript updates, key-schedule checkpoints, and protection activation boundaries.
- [QUIC integration](../quic/README.md) — TLS-derived secrets used by packet protection.

## 6. References
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 7366 — Encrypt-then-MAC for TLS and DTLS](https://www.rfc-editor.org/rfc/rfc7366)
