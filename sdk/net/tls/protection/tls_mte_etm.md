## MtE vs. EtM

### 1. MtE vs. EtM Architectural Diagrams

MtE (MAC-then-Encrypt) Protocol Processing
```
[ Input Parameters: encryption_key, mac_key, explicit_iv / implicit_iv, seq_num ]

< Sender Operations >
Header + Plaintext ─────> HMAC(mac_key, seq_num || Header || Plaintext) ─────> Tag
                                                                               │
                                                                               ▼
[ Ciphertext ] <── AES-CBC-Encrypt(encryption_key, IV) <── [ Plaintext || Tag || Padding ]

──────────────────────────────────────────────────────────────────────────────────────────

< Receiver Operations >
[ Ciphertext ] ──> AES-CBC-Decrypt(encryption_key, IV) ──> [ Plaintext || Tag || Padding ]
                                                                     │
                                                       1. Validate Padding
                                                       2. Extract Tag
                                                       3. Compute & Compare HMAC
                                                                     │
                                                                     ▼
                                                   Failure triggers Padding Oracle
                                                   / Timing Attacks (e.g., Lucky Thirteen)
```

EtM (Encrypt-then-MAC, RFC 7366) Protocol Processing
```
[ Input Parameters: encryption_key, mac_key, explicit_iv / implicit_iv, seq_num ]

< Sender Operations >
Plaintext ───> AES-CBC-Encrypt(encryption_key, IV) ───> Ciphertext
                                                             │
 Header + IV + Ciphertext ───────────────────────────────────┼──> HMAC(mac_key, seq_num || Header || IV || Ciphertext)
                                                             │    │
                                                             ▼    ▼
                                                  [ Ciphertext || Tag ]

──────────────────────────────────────────────────────────────────────────────────────────

< Receiver Operations >
[ Ciphertext || Tag ] ───> HMAC Verification(mac_key, seq_num || Header || IV || Ciphertext)
                                     │
                                     ├─> [ Mismatch ] ──> Terminate & Send Alert (No Decryption)
                                     │
                                     └─> [ Match ]    ──> AES-CBC-Decrypt(encryption_key, IV) ──> Plaintext
-----------------------------------------------------------------------------------------
```

### 2. Comprehensive Comparison Matrix

| Security & Structural Property | MtE (MAC-then-Encrypt) | EtM (Encrypt-then-MAC) | AEAD (TLS 1.3 / GCM / ChaCha20-Poly1305) |
| -- | -- | -- | -- |
| MAC Input Data | seq_num \|\| Header \|\| Plaintext | seq_num \|\| Header \|\| IV \|\| Ciphertext | Associated Data (seq_num \|\| Header) |
| Encryption Input Data | Plaintext \|\| MAC \|\| Padding | Plaintext | Plaintext |
| Authentication Target | Plaintext Data | Encrypted Record Packet | Plaintext + Associated Data (AAD) |
| First Operation on Receiver | CBC Decryption & Padding Removal | HMAC Verification over Ciphertext | AEAD Decrypt & Authenticate (Single Pass) |
| Padding Oracle Vulnerability | Vulnerable (Decryption precedes authentication) | Immune (Malformed packets dropped before decryption) | Immune (No CBC padding; implicit framing) |
| Standard References | Standard TLS 1.2 CBC suites | RFC 7366 Extension for TLS 1.2 | TLS 1.3 Mandatory Standard (RFC 8446) |

### 3. Key Technical Enhancements

- Implicit vs. Explicit IV Handling:
  - TLS 1.0 (MtE): Utilized implicit CBC IVs derived from the previous record's final ciphertext block, exposing the protocol to BEAST attacks.
  - TLS 1.1 / 1.2 (MtE & EtM): Shifted to explicit per-record IVs prepended to the ciphertext. Under EtM (RFC 7366), this explicit IV must be included inside the HMAC input payload to prevent IV tampering attacks.
- Timing Vulnerability Root Cause (Lucky Thirteen):
  - In MtE, checking HMAC validity requires stripping padding first. If padding is invalid, the receiver terminates early; if padding is valid, it computes HMAC over the unpadded length.
  - This subtle computation time differential reveals valid padding boundaries to network adversaries. EtM eliminates this by verifying MAC before any payload parsing or decryption occurs.
- Consolidation into AEAD in TLS 1.3:
  - TLS 1.3 completely removes legacy CBC mode and MAC-then-Encrypt mechanisms.
  - Encryption and authentication are unified into single-pass Authenticated Encryption with Associated Data (AEAD) primitives (AES-GCM, AES-CCM, ChaCha20-Poly1305), effectively enforcing Encrypt-and-Authenticate semantics at the cipher interface level.
