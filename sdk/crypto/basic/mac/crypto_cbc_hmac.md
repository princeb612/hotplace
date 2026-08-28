## Analysis of CBC-HMAC Combined AEAD Processing - published by Gemini

---

### 1. Overview and Core Concepts

* **Module Role**: An AEAD (Authenticated Encryption with Associated Data) processing module combining AES-CBC symmetric encryption and HMAC authentication.
* **Supported Specifications and Mechanisms**:
  * **JOSE (EtM)**: Encrypt-then-MAC scheme based on RFC 7516. Returns the tag separately as a `separated tag`.
  * **TLS MtE**: Mac-then-Encrypt scheme defined in TLS 1.2 standard (`nested tag`).
  * **TLS EtM**: Encrypt-then-MAC scheme defined in RFC 7366 extension standard (`concatenated tag`).
* **C++11 and Design Features**:
  * Reference counting-based memory management (`addref`, `release`) using `t_shared_reference`.
  * Exception and resource release control using `__try2`, `__leave2`, and `__finally2` macro statements.
  * Fluent Interface style algorithm/flag configuration (`set_enc().set_mac().set_flag()`).

---

### 2. Main Class and Method Structure

```cpp
namespace hotplace {
namespace crypto {

class crypto_cbc_hmac {
   public:
    crypto_cbc_hmac();

    // Configuration interfaces (Fluent)
    crypto_cbc_hmac& set_enc(crypt_algorithm_t enc_alg);
    crypto_cbc_hmac& set_mac(hash_algorithm_t mac_alg);
    crypto_cbc_hmac& set_flag(uint16 flag);  // jose_encrypt_then_mac, tls_mac_then_encrypt, tls_encrypt_then_mac

    // Key Splitting Helper (Key = MAC_KEY || ENC_KEY)
    return_t split_key(const binary_t key, binary_t& enckey, binary_t& mackey) const;

    // Concatenated / Nested Tag (TLS mode)
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext, binary_t& ciphertext) const;
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext) const;

    // Separated Tag (JOSE mode)
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext, binary_t& ciphertext, binary_t& tag) const;
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext, const binary_t& tag) const;

    void addref();
    void release();
};

}  // namespace crypto
}  // namespace hotplace

```

---

### 3. Operating Mechanism and Processing Flow per Flag

* **`split_key` (Key Splitting)**:
  * Splits the input master `key` so that the upper bytes become the MAC key and the lower bytes become the encryption key (ENC key).
  * Truncates the HMAC digest size in half according to JOSE specifications.
* **TLS Mode (`encrypt` / `decrypt` overloading 1)**:
  * **`tls_mac_then_encrypt`**: Generates HMAC tag based on plaintext and AAD, then performs CBC encryption with padding.
  * **`tls_encrypt_then_mac`**: Performs CBC encryption, calculates HMAC tag based on ciphertext and AAD, and combines them into `ciphertext || tag` format.
* **JOSE Mode (`encrypt` / `decrypt` overloading 2)**:
  * **`jose_encrypt_then_mac`**: Generates CBC ciphertext $Q$, then computes and truncates the Tag using the formula $MAC(MAC\_KEY, AAD \mid\mid IV \mid\mid Q \mid\mid AL)$.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-CBCHMAC-01** | Apply constant-time comparison functions during JOSE mode HMAC tag calculation (Timing Attack prevention) | High | Open |
| **TODO-CBCHMAC-02** | Reinforce padding validation and error handling logic during `tls_mac_then_encrypt` decryption (mitigation against Lucky Thirteen attack) | High | Open |
| **TODO-CBCHMAC-03** | Add unit tests for `split_key` and JWE A128CBC-HS256 vector validation cases | Medium | In Progress |
| **TODO-CBCHMAC-04** | Consider refactoring internal reference management to C++11 `std::shared_ptr`<br> | Low | Open |
