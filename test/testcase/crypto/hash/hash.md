## Hash & HMAC / OTP Engine Test Suite - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: Hash 함수, HMAC 및 OTP (HOTP/TOTP), Transcript Hash 연산의 unit test 및 표준 RFC Test Vector 검증 module (`hash/`).
* **주요 기능**:
  * **OpenSSL Hash Engine Verification**: OpenSSL wrapper 기반 hash 연산 동작 검증 (`testcase_openssl_hash.cpp`).
  * **Standard RFC Test Vector Parsing**: RFC 4226 (HOTP), RFC 4231 (HMAC-SHA-224/256/384/512), RFC 4493 (AES-CMAC), RFC 6238 (TOTP) 규격 검증 (`testcase_rfc4226.cpp`, `testcase_rfc4231.cpp`, `testcase_rfc4493.cpp`, `testcase_rfc6238.cpp`).
  * **Handshake Transcript Hash Verification**: TLS/QUIC handshake 과정에서 사용하는 Transcript Hash 연산 검증 (`testcase_transcript_hash.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **OpenSSL & Transcript Hash Testcases (`testcase_openssl_hash.cpp`, `testcase_transcript_hash.cpp`)**:
  * OpenSSL 기반 SHA-2 / SHA-3 hash 연산 및 Digest 누적 연산 검증.
  * TLS 1.3 Handshake message 누적에 따른 Transcript Hash 업데이트 및 Digest 추출 연산 확인.
* **RFC Standard Testcases (`testcase_rfc*.cpp`)**:
  * **RFC 4226 (HOTP)**: HMAC-SHA-1 기반 Event-based OTP 생성 및 Truncation 연산 테스트.
  * **RFC 4231 (HMAC)**: HMAC-SHA-224/256/384/512 표준 키/입력 데이터 test vector parsing 및 검증.
  * **RFC 4493 (AES-CMAC)**: AES-128 기반 Cipher-based MAC 연산 및 Subkey 생성 검증.
  * **RFC 6238 (TOTP)**: Time-based OTP 생성 및 시간 스텝 단위 token parsing 테스트.

---

### 3. 핵심 동작 mechanism

* **Hash & OTP Verification Flow (`testcase_rfc*.cpp`)**:
  * RFC Known Input 주입 -> Hash / HMAC / CMAC / OTP 연산 수행 -> Known Output 과 결과 byte-by-byte comparison 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-CH-01** | `testcase_transcript_hash.cpp` 내 TLS 1.3 Handshake Context Reset 시 Memory Corruption 예외 처리 검증 | High | 미진행 |
| **TODO-CH-02** | `testcase_rfc6238.cpp` 내 32-bit time_t Overflow (Year 2038 Problem) 예외 처리 확인 | High | 미진행 |
| **TODO-CH-03** | `testcase_rfc4493.cpp` 내 AES-CMAC Invalid Key Size 입력 시 Boundary Check 보완 | Medium | 미진행 |
| **TODO-CH-04** | `testcase_openssl_hash.cpp` 내 EVP_MD_CTX 생명주기 관리 시 Resource Leak 여부 static analysis 검증 | Low | 미진행 |
