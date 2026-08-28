## JOSE (JSON Object Signing and Encryption) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 library module that handles JSON data encryption, signing, and key management by implementing JOSE standard specifications such as RFC 7515 (JWS), RFC 7516 (JWE), and RFC 7517 (JWK).
* **Key Features**:
  * **JWE (JSON Object Encryption)**: Supports JSON data encryption through `json_object_encryption` and builder-style `json_object_encryption_composer`.
  * **JWS (JSON Object Signing)**: Provides JSON message integrity verification and signatures using `json_object_signing` and `json_object_signing_composer`.
  * **JWS + JWE Combination**: Supports nested processing for Sign-then-Encrypt using `json_object_signing_encryption`.
  * **JWK and Signature Management**: Abstract cryptography key sets and digital signature objects via `json_web_key` and `json_web_signature` classes.
* **C++11 Features**:
  * Implements a method chaining interface utilizing the Builder/Composer pattern.
  * Uses `std::vector<uint8_t>` and `std::string` for internal buffer management, and defines `types.hpp` for type safety.

---

### 2. Main Class and API Structure

**JOSE Core Objects and Builder Structure**

```cpp
namespace hotplace {

// JWK (JSON Web Key) and Signature Management
class json_web_key;
class json_web_signature;

// JWE Encryption Class and Builder
class json_object_encryption;
class json_object_encryption_composer;

// JWS Signature Class and Builder
class json_object_signing;
class json_object_signing_composer;

// JWS + JWE Signature and Encryption Combined Class
class json_object_signing_encryption;

}  // namespace hotplace

```

---

### 3. Core Operating Mechanism

* **JWS/JWE Composer (Builder Pattern)**:
  * `json_object_signing_composer` and `json_object_encryption_composer`: Configures headers (Algorithm, Enc, Kid, etc.), specifies payload, and links keys step-by-step to assemble and encode into final Compact/JSON Serialization format.
* **Sign-then-Encrypt (`json_object_signing_encryption`)**:
  * Performs JWS signature on original data first, then passes the resulting JWS payload into JWE to process nested encryption layers.
* **Key and Signature Verification (`json_web_key`, `json_web_signature`)**:
  * Converts RSA/ECC/Symmetric key structures to and from standard JWK format via `json_web_key`, and performs signature verification using `json_web_signature`.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-JOSE-01** | Refine AEAD encryption tag validation logic for AES-GCM, ChaCha20-Poly1305, etc. in `json_object_encryption` | High | Open |
| **TODO-JOSE-02** | Strengthen exception handling logic for unsupported algorithms (`alg`) or key types (`kty`) during `json_web_key` parsing | High | Open |
| **TODO-JOSE-03** | Add Rvalue Reference / Move setters to `json_object_signing_composer` and `encryption_composer` to minimize memory copying | Medium | Open |
| **TODO-JOSE-04** | Improve multi-key lookup algorithms and `kid`-based key matching performance for JWK Sets (JWKS) | Low | Open |
