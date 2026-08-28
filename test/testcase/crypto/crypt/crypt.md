## Crypt (Symmetric Encryption & AEAD) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A unit test and external Test Vector verification module for symmetric encryption, AEAD (Authenticated Encryption with Associated Data), and Key Wrap modules (`crypt/`).
* **Key Features**:
  * **Symmetric Cipher & AEAD Testing**: Verifies block cipher (AES, ChaCha20, etc.) encryption/decryption and AEAD mode (CCM, GCM, Poly1305) operations (`testcase_cipher_encrypt.cpp`, `testcase_aead_ccm.cpp`, `testcase_crypto_aead.cpp`).
  * **OpenSSL Crypt Integration Validation**: Verifies symmetric encryption operations based on OpenSSL wrapper integration (`testcase_openssl_crypt.cpp`).
  * **Standard Test Vector Parsing**: Performs Known Answer Test (KAT) verification based on YAML specifications, including CAVP, JOSE (CBC-HMAC), TLS (CBC-HMAC), RFC 3394 (AES Key Wrap), and RFC 7539 (ChaCha20-Poly1305) (`testvector_*.cpp`, `testvector_*.yml`).

---

### 2. Core Implementation Areas and Technical Elements

* **Cipher & AEAD Testcases (`testcase_*.cpp`)**:
  * Performs qualitative verification of block cipher encryption/decryption and verifies padding handling (`testcase_cipher_encrypt.cpp`, `testcase_crypto_encrypt.cpp`).
  * Verifies authentication tag validation and Associated Data (AAD) handling during AES-CCM / GCM and ChaCha20-Poly1305 AEAD operations (`testcase_aead_ccm.cpp`, `testcase_crypto_aead.cpp`).
* **Test Vector Engine (`testvector_*.cpp`, `*.yml`)**:
  * **CAVP**: Verifies NIST CAVP (Cryptographic Algorithm Validation Program) block cipher test vectors (`testvector_cavp_blockciphers.cpp`).
  * **JOSE & TLS**: Parses and verifies AES-CBC + HMAC-SHA combined test vectors under JOSE and TLS specifications (`testvector_cbc_hmac_jose.cpp`, `testvector_cbc_hmac_tls.cpp`).
  * **RFC Standard Vectors**: Verifies RFC 3394 (AES Key Wrap) and RFC 7539 (ChaCha20-Poly1305) implementations (`testvector_rfc3394.cpp`, `testvector_rfc7539.cpp`).

---

### 3. Core Operating Mechanism

* **Test Vector Verification Flow (`testvector_*.cpp`)**:
  * Loads and parses YAML test vectors $\rightarrow$ Injects Plaintext, Key, IV, and AAD $\rightarrow$ Performs Cipher/AEAD encryption operations $\rightarrow$ Executes byte-by-byte comparison operations to ensure Ciphertext and Authentication Tag match KAT expected outputs.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-CC-01** | Verify exception handling for ChaCha20-Poly1305 nonce reuse and tag mismatches in `testvector_rfc7539.cpp`<br> | High | Open |
| **TODO-CC-02** | Verify buffer overflow and memory corruption prevention upon invalid tag or AAD mismatch in `testcase_aead_ccm.cpp`<br> | High | Open |
| **TODO-CC-03** | Optimize large CAVP YAML file parsing performance in `testvector_cavp_blockciphers.cpp`<br> | Medium | Open |
| **TODO-CC-04** | Verify key data memory wiping during AES Key Wrap / Unwrap operations in `testvector_rfc3394.cpp`<br> | Low | Open |
