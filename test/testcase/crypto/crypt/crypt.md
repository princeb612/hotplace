## Crypt (Symmetric Encryption & AEAD Engine) Test Suite & Test Vectors - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 대칭키 암호화(Symmetric Encryption), AEAD(Authenticated Encryption with Associated Data) 및 Key Wrap module의 unit test 및 외부 Test Vector 검증 module (`crypt/`).
* **주요 기능**:
  * **Symmetric Cipher & AEAD Testing**: Block Cipher (AES, ChaCha20 등) 암복호화 및 AEAD 모드 (CCM, GCM, Poly1305) 연산 검증 (`testcase_cipher_encrypt.cpp`, `testcase_aead_ccm.cpp`, `testcase_crypto_aead.cpp`).
  * **OpenSSL Crypt Integration Validation**: OpenSSL wrapper 연동 기반 대칭 암호화 동작 검증 (`testcase_openssl_crypt.cpp`).
  * **Standard Test Vector Parsing**: CAVP, JOSE (CBC-HMAC), TLS (CBC-HMAC), RFC 3394 (AES Key Wrap), RFC 7539 (ChaCha20-Poly1305) 등 YAML 규격 기반 KAT (Known Answer Test) 검증 (`testvector_*.cpp`, `testvector_*.yml`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Cipher & AEAD Testcases (`testcase_*.cpp`)**:
  * Block Cipher 암복호화 정성 검증 및 Padding handling 확인 (`testcase_cipher_encrypt.cpp`, `testcase_crypto_encrypt.cpp`).
  * AES-CCM / GCM 및 ChaCha20-Poly1305 AEAD 연산 시 Tag 검증 및 Associated Data (AAD) 처리 확인 (`testcase_aead_ccm.cpp`, `testcase_crypto_aead.cpp`).
* **Test Vector Engine (`testvector_*.cpp`, `*.yml`)**:
  * **CAVP**: NIST CAVP (Cryptographic Algorithm Validation Program) Block Cipher test vector 검증 (`testvector_cavp_blockciphers.cpp`).
  * **JOSE & TLS**: JOSE 및 TLS 사양의 AES-CBC + HMAC-SHA2 조합 test vector parsing 검증 (`testvector_cbc_hmac_jose.cpp`, `testvector_cbc_hmac_tls.cpp`).
  * **RFC Standard Vectors**: RFC 3394 (AES Key Wrap) 및 RFC 7539 (ChaCha20-Poly1305) 검증 (`testvector_rfc3394.cpp`, `testvector_rfc7539.cpp`).

---

### 3. 핵심 동작 mechanism

* **Test Vector Verification Flow (`testvector_*.cpp`)**:
  * YAML test vector load 및 parsing -> Plaintext, Key, IV, AAD 주입 -> Cipher/AEAD 암호화 연산 수행 -> Ciphertext 및 Authentication Tag 가 KAT expected output 과 일치하는지 byte-by-byte comparison 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-CC-01** | `testvector_rfc7539.cpp` 내 ChaCha20-Poly1305 Nonce Reuse 및 Tag Mismatch 에 대한 Exception Handling 검증 | High | 미진행 |
| **TODO-CC-02** | `testcase_aead_ccm.cpp` 내 Invalid Tag / AAD mismatch 발생 시 Memory Corruption 및 Buffer Overflow 검증 | High | 미진행 |
| **TODO-CC-03** | `testvector_cavp_blockciphers.cpp` 내 대용량 CAVP YML Parsing 연산 최적화 | Medium | 미진행 |
| **TODO-CC-04** | `testvector_rfc3394.cpp` 내 AES Key Wrap / Unwrap 연산 시 Key Data Memory Wipe 검증 | Low | 미진행 |
