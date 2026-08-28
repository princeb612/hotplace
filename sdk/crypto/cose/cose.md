## COSE (CBOR Object Signing and Encryption) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 library module that performs encryption, signing, MAC (message authentication code), and key management based on CBOR data structures in compliance with RFC 8152 / RFC 9052 (COSE) standards.
* **Key Features**:
  * **COSE Message Structure Handling**: Supports parameter structures including Protected/Unprotected Header (`cose_protected`, `cose_unprotected`), Payload, Recipient (`cose_recipient`, `cose_recipients`), and Countersign (`cose_countersign`, `cose_countersigns`).
  * **Encryption / Signing / MAC Operations**: Supports object operations based on `cbor_object_encryption` (COSE_Encrypt/COSE_Encrypt0), `cbor_object_signing` (COSE_Sign/COSE_Sign1), and MAC.
  * **Multi-layer and Builder Structure**: Provides the `cose_composer` builder pattern as well as nested signature/encryption operations (`cbor_object_signing_encryption_*`).
  * **COSE Key Management**: Parses and maps COSE Key / COSE Key Set data through `cose_key` and `cbor_web_key` modules.
* **C++11 Features**:
  * Implements a builder pattern-based chaining interface and handles binary buffers centered around `std::vector<uint8_t>`.
  * Utilizes `types.hpp` for common data types and constant abstraction.

---

### 2. Main Class and API Structure

**COSE Core Objects and Message Components**

```cpp
namespace hotplace {

// COSE Key and Header Management
class cose_key;
class cbor_web_key;
class cose_protected;
class cose_unprotected;

// Recipient and Countersign Structures
class cose_recipient;
class cose_recipients;
class cose_countersign;
class cose_countersigns;

// COSE Message Builder
class cose_composer;

// COSE Encryption / Signing / MAC Operation Classes
class cbor_object_encryption;
class cbor_object_signing;
class cbor_object_signing_encryption;

}  // namespace hotplace

```

---

### 3. Core Operating Mechanism

* **Message Assembly (`cose_composer`)**:
  * Sets Protected/Unprotected header properties and combines Payload data with Recipient/Countersign objects to generate the final CBOR-encoded COSE message structure.
* **Authentication and Encryption Operations (`cbor_object_signing_encryption_*`)**:
  * Encryption (`_crypt`), signing (`_sign`), and MAC (`_mac`) processing modules are separated, allowing flexible configuration from single-layer Sign1/Encrypt0 structures to complex structures containing multiple Recipients according to COSE specifications.
* **Header and Recipient Management (`cose_protected`, `cose_recipient`)**:
  * Protected headers are processed as integrity verification targets (CBOR bstr encoding), while `cose_recipients` hierarchically maintains key distribution (Key Transport/Key Agreement) parameters for each recipient.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-COSE-01** | Strengthen Nonce/IV size validation when processing AES-CCM and AES-GCM algorithms in `cbor_object_encryption`<br> | High | Open |
| **TODO-COSE-02** | Implement exception handling logic and verify compatibility for Countersign V2 structure based on RFC 9052 specification in `cose_countersign`<br> | High | Open |
| **TODO-COSE-03** | Add validation logic and prevent duplicate header parameter configuration in `cose_composer` builder | Medium | Open |
| **TODO-COSE-04** | Extend OKP (Ed25519/X25519) curve key mapping and strengthen validation when parsing `cose_key`<br> | Medium | Open |
