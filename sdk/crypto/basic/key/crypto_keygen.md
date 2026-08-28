## Analysis of OpenSSL-based TLS Key Exchange and PQC/Hybrid KEM - published by Gemini

---

### 1. Overview and Core Concepts

* **Module Role**: Provides abstraction for ECDHE, ML-KEM, and ECDHE-MLKEM hybrid key exchange mechanisms based on TLS 1.3 algorithm specifications.
* **C++11 and Design Features**:
  * Supports OpenSSL-based PQC (ML-KEM) and ECDH algorithms.
  * Resource and lifecycle management (`addref`, `release`) based on reference counting (`t_shared_reference`).
  * Single-exit error handling pattern applied using `__try2`, `__leave2`, and `__finally2` macro structures.
  * Supports hybrid combination schemes (combining EC/OKP with ML-KEM sequence) defined in RFC/Draft specifications.

---

### 2. Main Class and Core Methods

```cpp
namespace hotplace {
namespace crypto {

class crypto_keyexchange {
   public:
    crypto_keyexchange(tls_group_t group = tls_group_t{});
    ~crypto_keyexchange();

    // Key generation & Public share extraction
    return_t keygen(crypto_key* key, const char* kid, binary_t& share);

    // ECDHE Key exchange
    return_t exchange(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    // PQC / Hybrid ML-KEM Encapsulation & Decapsulation
    return_t encaps(const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret);
    return_t decaps(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    tls_group_t get_group() const;

    void addref();
    void release();
};

}  // namespace crypto
}  // namespace hotplace

```

---

### 3. Key Implementation Flow

* **Key Generation (`keygen`)**:
  * Collects specified `tls_group_t` hint information from `crypto_advisor`.
  * Generates key pairs and binds the public key (`share`) byte sequence depending on whether it is a single algorithm or a hybrid combination (`tls_flag_hybrid`).
* **Key Encapsulation (`encaps`)**:
  * Receives client's public key `share` and temporarily stores it via `keystore()`.
  * Executes ML-KEM encapsulation (`pqc.encapsule`) to derive the `keycapsule` and shared secret key (`sharedsecret`).
  * For hybrid groups, serializes and combines ECDH key agreement results according to specification (`secp256r1mlkem768`: EC || ML-KEM, `x25519mlkem768`: ML-KEM || X25519).
* **Key Decapsulation (`decaps`)**:
  * Validates encapsulated data specifications and executes `pqc.decapsule` using the private key.
  * Combines hybrid operation results to recover the final `sharedsecret`.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-KE-01** | Verify serialization order synchronization according to ML-KEM draft-ietf-tls-ecdhe-mlkem specification updates | High | In Progress |
| **TODO-KE-02** | Add multithread reference counting thread-safety test cases within `crypto_keyexchange`<br> | High | Open |
| **TODO-KE-03** | Define error logging and detailed return codes upon entering unsupported `tls_group_t`<br> | Medium | Open |
| **TODO-KE-04** | Implement OpenSSL 3.x PQC provider loading performance optimization and benchmark tests | Low | Open |
