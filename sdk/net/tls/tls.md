## TLS (Transport Layer Security) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: Core module implementing and parsing TLS/DTLS protocol record layers, handshake mechanisms, extensions, and cryptographic protection layers.
* **Key Features**:
  * **TLS/DTLS Record Management**: Parses and constructs `tls_record`, `dtls13_ciphertext`, and various record types (Handshake, Alert, Application Data, Change Cipher Spec, etc.).
  * **Handshake Message Processing**: Parses and builds TLS handshake messages including ClientHello, ServerHello, Certificate, CertificateVerify, Finished, NewSessionTicket, and others.
  * **Comprehensive TLS Extension Support**: Implements standard extensions such as SNI, ALPN, KeyShare, PreSharedKey, SupportedGroups, and QUIC Transport Parameters.
  * **Protection & Key Calculation (`tls_protection`)**: Executes AEAD/CBC-HMAC encryption, Keyblock/PSK calculations, Finished message validations, and Header Protection (HP) operations.
  * **TLS Advisor & SSLKeyLog**: Provides ciphersuite and parameter mapping details via `tls_advisor`, and supports SSLKeyLog Exporter/Importer capabilities.

---

### 2. Core Classes and Module Structure

**TLS Core Module Configuration**

```cpp
namespace hotplace {

// TLS session and advisor
class tls_session;
class tls_advisor;

// TLS record and handshake builder/parser
class tls_record;
class tls_record_builder;
class tls_handshake;
class tls_handshake_builder;

// TLS protection and encryption layer
class tls_protection;
class tls_protection_context;

// SSLKeyLog exporter/importer
class sslkeylog_exporter;
class sslkeylog_importer;

}  // namespace hotplace

```

---

### 3. Core Operating Mechanism

* **Record & Handshake Builder Structure (`tls_record_builder`, `tls_handshake_builder`)**:
  * Dynamically structures TLS record packets and handshake payloads using the object-oriented builder pattern.
* **Protection Layer Cryptographic Operations (`tls_protection`)**:
  * Derives unidirectional/bidirectional encryption keys for each handshake phase and applies AEAD (GCM/CCM) or CBC-HMAC schemes to secure messages.
* **DTLS & QUIC Integration Extensions**:
  * Handles DTLS packet retransmission and fragmentation via `dtls_record_arrange` and `dtls_handshake_fragmented`.
  * Provides `tls_extension_quic_transport_parameters` to support TLS 1.3-based QUIC handshake parameter exchanges.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-TLS-01** | Verify exception handling during TLS 1.3 secret derivation and Key Update mechanisms in `tls_protection_encryption_aead`<br> | High | Open |
| **TODO-TLS-02** | Add unit tests for Ed25519 and RSA-PSS signature verification logic in `tls_handshake_certificate_verify`<br> | High | Open |
| **TODO-TLS-03** | Refactor HPKE binding logic in `tls_extension_encrypted_client_hello` (ECH) following specification changes | Medium | Open |
| **TODO-TLS-04** | Optimize reassembly buffering during out-of-order delivery and packet loss scenarios in the `dtls_record_arrange` module | Medium | Open |
| **TODO-TLS-05** | Add logic to prevent missing TLS 1.3 Early Secret / Handshake Secret entries between `sslkeylog_exporter` and `sslkeylog_importer`<br> | Low | Open |
