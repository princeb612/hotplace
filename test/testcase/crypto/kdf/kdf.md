## Key Derivation Function (KDF) & Password Hashing - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A unit test and standard RFC Test Vector verification module for Key Derivation Functions (KDF) and password hashing algorithms, including HKDF, PBKDF2, scrypt, and Argon2 (`kdf/`).
* **Key Features**:
  * **HKDF Engine Verification**: Verifies HMAC-based Extract-and-Expand Key Derivation Function operations (`testcase_hkdf.cpp`).
  * **Standard RFC KDF Test Vector Parsing**: Verifies compliance with RFC 4615 (AES-CMAC PRF-128), RFC 5869 (HKDF), and RFC 6070 (PBKDF2) specifications (`testvector_rfc4615.cpp`, `testvector_rfc5869.cpp`, `testcase_rfc6070.cpp`).
  * **Password Hashing & Memory-Hard Function Verification**: Verifies RFC 7914 (scrypt) and RFC 9106 (Argon2d/Argon2i/Argon2id) operations (`testcase_rfc7914.cpp`, `testcase_rfc9106.cpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **KDF & Password Hashing Testcases (`testcase_*.cpp`)**:
  * **HKDF**: Verifies step-by-step Extract and Expand operations based on OpenSSL or internal implementations (`testcase_hkdf.cpp`).
  * **PBKDF2 (RFC 6070)**: Verifies HMAC-SHA1-based key derivation operations as iteration counts increase (`testcase_rfc6070.cpp`).
  * **scrypt (RFC 7914) & Argon2 (RFC 9106)**: Performs qualitative hash operation verification under memory-hard parameters, such as cost factor, block size, and parallelization (`testcase_rfc7914.cpp`, `testcase_rfc9106.cpp`).
* **Test Vector Engine (`testvector_*.cpp`, `*.yml`)**:
  * **RFC 4615**: Verifies variable key size processing based on AES-CMAC-PRF-128 (`testvector_rfc4615.cpp`).
  * **RFC 5869**: Parses standard SHA-1 and SHA-256 HKDF YAML test vectors and executes comparison verification (`testvector_rfc5869.cpp`).

---

### 3. Core Operating Mechanism

* **KDF Verification Flow (`testvector_*.cpp`, `testcase_*.cpp`)**:
  * Loads YAML/RFC known inputs, including IKM, Salt, Info, and cost parameters $\rightarrow$ Performs HKDF, PBKDF2, scrypt, or Argon2 key derivation operations $\rightarrow$ Executes byte-by-byte comparison operations to ensure derived keys match known outputs.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **CKD1** | Verify boundary checks and safe free operations upon Argon2 memory allocation failure in `testcase_rfc9106.cpp`<br> | High | Open |
| **CKD2** | Implement exception handling to prevent stack/heap exhaustion when configuring large cost factors ($N$) for scrypt in `testcase_rfc7914.cpp`<br> | High | Open |
| **CKD3** | Strengthen validation when exceeding the maximum output length ($255 \times \text{HashLen}$) during the HKDF Expand phase in `testvector_rfc5869.cpp`<br> | Medium | Open |
| **CKD4** | Review mitigation strategies for CPU spiking during high iteration count PBKDF2 operations in `testcase_rfc6070.cpp`<br> | Low | Open |
