## TLS key schedule

The following additions refine the TLS Key Schedule documentation by incorporating missing cryptographic steps, secret derivations, and protocol details.

### 1. TLS 1.2 vs TLS 1.3

- TLS 1.2:
  - Included IV Derivation (Client/Server Write IVs) alongside MAC and Encryption Keys within the Key Block.
  - Clarified that TLS 1.2 PRF relies on HMAC (MD5 + SHA-1 or SHA-256) depending on the cipher suite.
- TLS 1.3:
  - Complete HKDF Derivation Path: Added explicit derivation stages for Derived Secrets, Resumption Master Secret, and Exporter Master Secret.
  - Transcript Hash Integration: Emphasized that each stage uses HKDF-Expand-Label with the running Handshake Transcript Hash as context.
  - Key & IV Generation: Explicitly illustrated how actual key and iv pairs are derived from each Traffic Secret using HKDF-Expand-Label.

### 2. TLS Key Schedule

1. TLS 1.2 Key Derivation Flow

```
Client/Server Hello Randoms
          │
          ▼
   Pre-Master Secret ──────> [ PRF (HMAC-SHA256/384) ] ──────> Master Secret (48 Bytes)
                                       │
                                       ▼
                       [ PRF (Master Secret + "key expansion" + Randoms) ]
                                       │
                                       ▼
                                   Key Block
  ┌───────────────┬───────────────┬───────────────┬───────────────┬───────────────┬───────────────┐
  ▼               ▼               ▼               ▼               ▼               ▼
Client MAC      Server MAC     Client Enc      Server Enc      Client Write    Server Write
  Key             Key             Key             Key              IV              IV
```

- Pre-Master Secret to Master Secret: Generated via RSA key exchange or Ephemeral Diffie-Hellman (DHE/ECDHE). Derived using PRF with "master secret" label and Client/Server Randoms.
- Key Block Generation: A single contiguous Key Block is generated via PRF with "key expansion" label and sliced sequentially into 6 distinct parameters (MAC keys, Encryption keys, and Write IVs).

2. TLS 1.3 HKDF Key Schedule Flow

```
0 (Salt)
 │
 ▼
[ HKDF-Extract ] <── PSK (or 0s if unauthenticated)
 │
 ▼
Early Secret ───┬───> [ HKDF-Expand-Label ] ───> Client Early Traffic Secret ───> early key / iv
 │               └───> [ HKDF-Expand-Label ] ───> Early Exporter Master Secret
 ▼
[ Derive-Secret("derived", "") ]
 │
 ▼
[ HKDF-Extract ] <── ECDHE / DHE Shared Secret
 │
 ▼
Handshake Secret ───┬───> [ HKDF-Expand-Label ] ───> Client Handshake Traffic Secret ───> c_hs_key / iv
 │                  └───> [ HKDF-Expand-Label ] ───> Server Handshake Traffic Secret ───> s_hs_key / iv
 ▼
[ Derive-Secret("derived", "") ]
 │
 ▼
[ HKDF-Extract ] <── 0
 │
 ▼
Master Secret ───┬───> [ HKDF-Expand-Label ] ───> Client App Traffic Secret 0 ───> c_app_key / iv
                 ├───> [ HKDF-Expand-Label ] ───> Server App Traffic Secret 0 ───> s_app_key / iv
                 ├───> [ HKDF-Expand-Label ] ───> Exporter Master Secret
                 └───> [ HKDF-Expand-Label ] ───> Resumption Master Secret
```

### 3. Key Differences Summary

| Feature | TLS 1.2 | TLS 1.3 |
| -- | -- | -- |
| Derivation Mechanism | Custom PRF (HMAC-based) | Standardized HKDF (RFC 5869) |
| Key Generation Strategy | Monolithic Key Block sliced for all keys | Stage-based Secret Chain (Early $\rightarrow$ Handshake $\rightarrow$ Application) |
| Handshake Transcript Context | Not directly mixed into Master Secret | Every derived secret explicitly binds the current Transcript Hash |
| Key Update Support | Requires full renegotiation or session resumption | Native post-handshake key updates via HKDF-Expand-Label |
| IV Handling | Fixed IVs or explicit per-record IVs derived from Key Block | Implicit static IV derived per secret; XOR-masked with sequence numbers |
