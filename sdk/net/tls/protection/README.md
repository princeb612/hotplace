## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS protection

## 1. Role

`sdk/net/tls/protection` implements TLS/DTLS cryptographic protection and key-schedule operations: transcript hashing, Finished verification inputs, key-block/PSK calculations, and record encryption/decryption. Its behavior spans the handshake and record lifecycle; it is not owned conceptually by a single record object.

## 2. Data Model

Three related but distinct kinds of state cooperate:

- **Transcript state:** a running hash over protocol-defined handshake-message bytes, excluding record framing.
- **Derived secrets and traffic parameters:** TLS 1.2 master secret/key block versus TLS 1.3 staged secrets, traffic keys, and IVs.
- **Record protection inputs:** negotiated cipher/AEAD parameters, directional key/IV, record sequence context, header/AAD, plaintext or ciphertext, and authentication tag.

TLS 1.2 and TLS 1.3 must remain distinct: TLS 1.2 commonly derives a contiguous key block and supports legacy CBC/MAC constructions; TLS 1.3 uses HKDF-based staged derivation and AEAD. QUIC consumes TLS 1.3-derived secrets but applies QUIC packet protection, not TLS record protection.

## 3. Behavior Model

### Transcript → key schedule → protection

```text
handshake parser/session
  -> append protocol-defined handshake messages to transcript
  -> transcript checkpoint for the current handshake stage
  -> TLS 1.2 PRF/key-block OR TLS 1.3 HKDF key schedule
  -> directional traffic secret / key / IV
  -> record protection
       TLS/DTLS: record header + sequence/epoch context + protected content
       QUIC: packet number/header protection + packet AEAD
  -> peer verifies/decrypts and updates its corresponding state
```

The transcript hash is an input to stage-specific TLS 1.3 derivations and Finished verification; the key schedule produces the material used by protection; AEAD consumes keys/IVs and protocol-defined associated data to authenticate ciphertext and context. These stages are connected, but they are not one function and do not advance at the same time. The handshake/session code decides when messages enter the transcript and when newly derived keys become active.

TLS 1.2 MtE and EtM describe legacy CBC authentication ordering; TLS 1.3 uses AEAD and does not use those legacy CBC suites. QUIC's packet number and header protection belong to the QUIC packet layer, even when the traffic secrets originate from TLS.

## 4. Relationships

- [TLS key schedule](tls_key_schedule.md) — TLS 1.2 key block and TLS 1.3 staged derivation.
- [Transcript hash](tls_transcript_hash.md) — transcript input and stage checkpoints.
- [MtE vs EtM](tls_mte_etm.md) — legacy CBC authentication order and AEAD distinction.
- `tls_protection_calc.cpp`, `tls_protection_calc_finished.cpp`, `tls_protection_calc_keyblock.cpp`, `tls_protection_calc_psk.cpp`.
- `tls_protection_context.cpp`, `tls_protection_encryption_aead.cpp`, `tls_protection_encryption_cbchmac.cpp`, `tls_protection_hash.cpp`, `tls_protection_hp.cpp`.
- `sdk/crypto/basic/kdf/`, `digest/`, `crypt/`, and `mac/` — lower-level derivation and cryptographic primitives.
- [TLS session support](../session/README.md) — decides handshake stage and state transition.
- [QUIC integration](../quic/README.md) — TLS-derived secrets used by packet protection.

## 5. References

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 7366 — Encrypt-then-MAC for TLS and DTLS](https://www.rfc-editor.org/rfc/rfc7366)
