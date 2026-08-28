## Hash & HMAC / OTP - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A unit test and standard RFC Test Vector verification module for Hash functions, HMAC, OTP (HOTP/TOTP), and Transcript Hash operations (`hash/`).
* **Key Features**:
  * **OpenSSL Hash Engine Verification**: Verifies hash operations based on OpenSSL wrapper integration (`testcase_openssl_hash.cpp`).
  * **Standard RFC Test Vector Parsing**: Verifies compliance with RFC 4226 (HOTP), RFC 4231 (HMAC-SHA-224/256/384/512), RFC 4493 (AES-CMAC), and RFC 6238 (TOTP) specifications (`testcase_rfc4226.cpp`, `testcase_rfc4231.cpp`, `testcase_rfc4493.cpp`, `testcase_rfc6238.cpp`).
  * **Handshake Transcript Hash Verification**: Verifies Transcript Hash operations used during TLS/QUIC handshake processes (`testcase_transcript_hash.cpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **OpenSSL & Transcript Hash Testcases (`testcase_openssl_hash.cpp`, `testcase_transcript_hash.cpp`)**:
  * Verifies OpenSSL-based SHA-2 / SHA-3 hash operations and digest accumulation.
  * Verifies Transcript Hash updates and digest extraction operations as TLS 1.3 handshake messages accumulate.
* **RFC Standard Testcases (`testcase_rfc*.cpp`)**:
  * **RFC 4226 (HOTP)**: Tests HMAC-SHA-1-based event-based OTP generation and truncation operations.
  * **RFC 4231 (HMAC)**: Parses and verifies standard key/input data test vectors for HMAC-SHA-224/256/384/512.
  * **RFC 4493 (AES-CMAC)**: Verifies AES-128-based Cipher-based MAC operations and subkey generation.
  * **RFC 6238 (TOTP)**: Tests Time-based OTP generation and token parsing per time step.

---

### 3. Core Operating Mechanism

* **Hash & OTP Verification Flow (`testcase_rfc*.cpp`)**:
  * Injects RFC Known Inputs $\rightarrow$ Executes Hash / HMAC / CMAC / OTP operations $\rightarrow$ Performs byte-by-byte comparison operations between results and Known Outputs.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-CH-01** | Verify memory corruption exception handling upon TLS 1.3 Handshake Context Reset in `testcase_transcript_hash.cpp` | High | Open |
| **TODO-CH-02** | Verify 32-bit `time_t` overflow (Year 2038 Problem) exception handling in `testcase_rfc6238.cpp` | High | Open |
| **TODO-CH-03** | Supplement boundary checks for invalid key size inputs in `testcase_rfc4493.cpp` (AES-CMAC) | Medium | Open |
| **TODO-CH-04** | Perform static analysis verification for resource leaks during `EVP_MD_CTX` lifecycle management in `testcase_openssl_hash.cpp` | Low | Open |
