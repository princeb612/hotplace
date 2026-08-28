## JOSE (JSON Object Signing and Encryption) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 library module that implements JOSE standard specifications such as RFC 7515 (JWS), RFC 7516 (JWE), and RFC 7517 (JWK) to process JSON data encryption, signing, and key management.
* **Key Features**:
  * **JWE (JSON Object Encryption)**: Supports JSON data encryption through `json_object_encryption` and the builder-style `json_object_encryption_composer`.
  * **JWS (JSON Object Signing)**: Provides JSON message integrity verification and digital signatures using `json_object_signing` and `json_object_signing_composer`.
  * **Combined JWS + JWE**: Supports nested Sign-then-Encrypt operations via `json_object_signing_encryption`.
  * **JWK and Signature Management**: Abstractly represents cryptographic key sets and digital signature objects via the `json_web_key` and `json_web_signature` classes.
* **C++11 Features**:
  * Implements a method-chaining interface using the Builder/Composer pattern.
  * Uses `std::vector<uint8_t>` and `std::string` for internal buffer management, and defines type safety via `types.hpp`.

---

### 2. Core Classes and API Structure

**JOSE Core Objects and Builder Structure**

```cpp
namespace hotplace {

// JWK (JSON Web Key) and Signature Management
class json_web_key;
class json_web_signature;

// JWE Encryption Class and Builder
class json_object_encryption;
class json_object_encryption_composer;

// JWS Signing Class and Builder
class json_object_signing;
class json_object_signing_composer;

// JWS + JWE Integrated Signing and Encryption Class
class json_object_signing_encryption;

}  // namespace hotplace

```

---

### 3. Core Operating Mechanism

* **JWS/JWE Composer (Builder Pattern)**:
  * `json_object_signing_composer` and `json_object_encryption_composer`: Assembles headers (Algorithm, Enc, Kid, etc.), specifies payload, and attaches keys step-by-step to encode the final output into Compact or JSON Serialization formats.
* **Sign-then-Encrypt (`json_object_signing_encryption`)**:
  * Performs a JWS signature on the raw data first, then passes the resulting JWS payload into JWE to create a nested encryption layer.
* **Key and Signature Verification (`json_web_key`, `json_web_signature`)**:
  * Converts RSA/ECC/Symmetric key structures to and from standard JWK formats via `json_web_key`, and executes signature verifications using `json_web_signature`.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-JOSE-01** | Refine AEAD authentication tag verification logic for AES-GCM and ChaCha20-Poly1305 in `json_object_encryption`<br> | High | Open |
| **TODO-JOSE-02** | Strengthen exception handling logic when parsing unsupported algorithms (`alg`) or key types (`kty`) in `json_web_key`<br> | High | Open |
| **TODO-JOSE-03** | Add rvalue reference/move setters to `json_object_signing_composer` and `encryption_composer` to minimize memory copying | Medium | Open |
| **TODO-JOSE-04** | Optimize performance algorithms for multi-key lookup and `kid`-based key matching in JWK Sets (JWKS) | Low | Open |
