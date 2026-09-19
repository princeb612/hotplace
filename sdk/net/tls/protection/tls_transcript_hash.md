## Transcript Hash

### 1. Standard Handshake Transcript Accumulation

```
[ Handshake Messages Sequence ]
┌─────────────────────────────────────────┐
│ ClientHello                             │ ───> Hash 1: SHA-256/384(ClientHello)
│ + ServerHello                           │ ───> Hash 2: SHA-256/384(CH || SH)
│ + EncryptedExtensions                   │ ───> Hash 3: SHA-256/384(CH || SH || EE)
│ + Certificate                           │ ───> Hash 4: SHA-256/384(... || Cert)
│ + CertificateVerify                     │ ───> Hash 5: SHA-256/384(... || CertVerify)
│ + Finished                              │ ───> Hash 6: SHA-256/384(... || Finished)
└─────────────────────────────────────────┘
```

- Definition: A continuous cryptographic hash computed over the exact unencrypted sequence of all exchanged handshake message bytes (excluding record layer framing).
- Core Purpose: Guarantees transcript integrity against Man-in-the-Middle (MITM) tampering, downgrade attacks, and forms the contextual binding parameter for key derivation functions (HKDF-Expand-Label).

### 2. HelloRetryRequest (HRR) & Synthetic Handshake Message (message_hash)

Construction Diagram
```
[ ClientHello1 Payload ]
           │
           ▼ (Hash Computation)
[ Hash(ClientHello1) ] ─────┐
                            ├─> [ 0xFE (Handshake Type: message_hash) ]
                            ├─> [ 0x00, 0x00, Hash_Length ] (3-Byte Length Header)
                            └─> [ Hash(ClientHello1) Payload ]
                                          │
                                          ▼
                         Synthetic Handshake Message (message_hash)
```

HRR Transcript Flow
```
+-----------------------------------------------------------------------+
|  Synthetic Handshake Message (message_hash)                           |
|  ├─ Type: 0xFE (HandshakeType.message_hash)                           |
|  ├─ Length: Hash Size (e.g., 32 bytes for SHA-256)                    |
|  └─ Payload: Hash(ClientHello1)                                       |
+-----------------------------------------------------------------------+
                                   │
                                   ▼
+-----------------------------------------------------------------------+
|  HelloRetryRequest                                                    |
+-----------------------------------------------------------------------+
                                   │
                                   ▼
+-----------------------------------------------------------------------+
|  ClientHello2                                                         |
+-----------------------------------------------------------------------+
                                   │
                                   ▼
          Transcript Hash = SHA-256/384(message_hash || HRR || CH2)
```

- Substitution Rule: ClientHello1 bytes are never appended directly when HRR occurs. Instead, ClientHello1 is replaced by the 4-byte header plus hash payload message_hash.
- Header Structure:
  - Type (1 byte): 0xFE (HandshakeType.message_hash)
  - Length (3 bytes): Digest byte count (e.g., 0x000020 for SHA-256, 0x000030 for SHA-384)
  - Payload: Raw hash digest of ClientHello1
- Design Rationale: Enables stateless server HRR handling and avoids buffering oversized ClientHello1 messages while enforcing cryptographic continuity across parameter negotiation retries.

### 3. 0-RTT Handshake Transcript & Boundary Map

0-RTT Flow Diagram
```
Client                                                              Server
======                                                              ======

ClientHello
  + early_data ext.
  + psk_key_exchange_modes ext.
  + pre_shared_key ext.
   │
   ├─────────────────────────────────────────────────────────────────>
   │
   │ [Transcript 1: ClientHello]
   │    │
   │    └─> HKDF-Extract/Expand(Early Secret, Transcript 1)
   │           └─> Client Early Traffic Secret / Key
   │
   │ [0-RTT Encrypted Application Data] (Encrypted via Client Early Key)
   ├─────────────────────────────────────────────────────────────────>
   │
   │                                              ServerHello
   │                                                + pre_shared_key ext.
   │                                              EncryptedExtensions
   │                                                + early_data ext. (If accepted)
   │ <────────────────────────────────────────────────────────────────
   │
   │ [Transcript 2: ClientHello + ServerHello + EncryptedExtensions]
   │    │
   │    └─> HKDF-Extract/Expand(Handshake Secret, Transcript 2)
   │           └─> Handshake Traffic Keys
   │
   │                                              Finished
   │ <────────────────────────────────────────────────────────────────
   │
   │ [Transcript 3: CH + SH + EE + ... + Server Finished]
   │
   │ EndOfEarlyData (TLS 1.3 only; omitted in DTLS 1.3)
   ├─────────────────────────────────────────────────────────────────>
   │
   │ Finished
   ├─────────────────────────────────────────────────────────────────>
   │
   │ [Transcript 4: CH + SH + EE + ... + Client Finished]
   │    │
   │    └─> HKDF-Extract/Expand(Master Secret, Transcript 4)
   │           └─> Application Traffic Keys
   │
   [1-RTT Application Data] <========================================>
```

Transcript Ranges & Derivation Contexts
| Phase / Key Target | Transcript Input Scope | Functional Description |
| -- | -- | -- |
| PSK Binder Verification | Truncated ClientHello (Up to pre_shared_key binder list) | Computes the HMAC binder verifying ownership of the PSK prior to transmission. |
| Early Traffic Keys | ClientHello | Encrypts 0-RTT application payloads before server handshake verification. |
| Handshake Traffic Keys | ClientHello + ServerHello + EncryptedExtensions | Encrypts control plane handshake messages after algorithm negotiation. |
| Client Finished Key | ClientHello + ... + Server Finished [+ EndOfEarlyData] | Binds server response and early data state transition (EndOfEarlyData). |
| Application Traffic Keys | ClientHello + ... + Client Finished | Final operational transcript hash used for standard bidirectional app data. |

### 4. Edge Cases & Protocol Nuances

- 0-RTT Application Data Exclusions: Application payloads (early data records) are record-layer frames and are strictly excluded from transcript hashing.
- 0-RTT Rejection Handling: If the server rejects 0-RTT, it omits the early_data extension in EncryptedExtensions. Early ciphertext is discarded by the server, but the transcript continues sequentially using the original ClientHello without re-calculation.
- EndOfEarlyData Protocol Differences:
  - TLS 1.3 (RFC 8446): Requires explicit EndOfEarlyData handshake message to mark epoch transition, which is accumulated into the transcript hash.
  - DTLS 1.3 (RFC 9147): Omits EndOfEarlyData entirely because record layer epoch headers explicitly define key transition boundaries.  
