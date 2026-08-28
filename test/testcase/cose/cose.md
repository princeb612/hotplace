# COSE (CBOR Object Signing and Encryption) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 library module that performs binary/CBOR-based encryption, signing, MAC generation, and key validation in compliance with RFC 8152, RFC 8778, RFC 9052 (COSE) standard specifications, and the latest PQC (post-quantum cryptography, ML-DSA) specifications.
* **Key Features**:
  * **RFC Official Test Vector Verification**: Executes automated verification based on RFC 8152, RFC 8392 (CWT), RFC 8778, RFC 9338, and AKP (ML-DSA 44/65/87) test vectors.
  * **COSE Message Structure Handling**: Manages parameters such as Protected/Unprotected Headers (`cose_protected`, `cose_unprotected`), Payload, Recipient (`cose_recipient`, `cose_recipients`), and Countersign (`cose_countersign`, `cose_countersigns`).
  * **Encryption / Signing / MAC Operations**: Supports `cbor_object_encryption` (COSE_Encrypt/COSE_Encrypt0), `cbor_object_signing` (COSE_Sign/COSE_Sign1), and MAC operations.
  * **Multi-Layer and Builder Structure**: Provides the `cose_composer` builder pattern and nested signing/encryption operations (`cbor_object_signing_encryption_*`).
  * **COSE Key Management**: Parses and maps COSE Keys / COSE Key Sets via `cose_key` and `cbor_web_key`.
* **C++11 Features**:
  * Implements a builder pattern-based chaining interface and handles binary data centered around `std::vector<uint8_t>`.
  * Utilizes `types.hpp` for common data types and constant abstraction.

---

### 2. Core Classes and API Structure

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
  * Configures Protected/Unprotected header properties and combines Payload, Recipient, and Countersign objects to generate the final CBOR-encoded COSE message structure.
* **Standard & PQC Verification Mechanism (`testcase_rfc8152.cpp`, `testcase_akp.cpp`)**:
  * Cross-verifies diagnostic format (`.diag`) and CBOR binary (`.cbor`) test vectors under RFC 8152/8778/9338 specifications.
  * Verifies post-quantum cryptography signature test vectors based on ML-DSA (44/65/87) Algorithmic Key Pairs (AKP).
* **Authentication and Encryption Operations (`cbor_object_signing_encryption_*`)**:
  * Separates encryption (`_crypt`), signing (`_sign`), and MAC (`_mac`) modules to handle operations ranging from single-layer Sign1/Encrypt0 structures to complex structures with multiple recipients.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-COSE-01** | Strengthen Nonce/IV size validation when processing AES-CCM and AES-GCM algorithms in `cbor_object_encryption`<br> | High | Open |
| **TODO-COSE-02** | Verify Countersign V2 structure compatibility based on the RFC 9052 specification and implement exception handling logic in `cose_countersign`<br> | High | Open |
| **TODO-COSE-03** | Add validation logic and prevent duplicate header parameter configurations within the `cose_composer` builder | Medium | Open |
| **TODO-COSE-04** | Expand OKP (Ed25519/X25519) curve key mapping and strengthen validation when parsing `cose_key`<br> | Medium | Open |
| **TODO-COSE-05** | Refine error codes and specialize exceptions when key lengths are invalid during ML-DSA (PQC) algorithm operations | Medium | Open |
