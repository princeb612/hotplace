## Key Derivation Function (KDF) & Password Hashing Engine Test Suite - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: HKDF, PBKDF2, scrypt, Argon2 등 Key Derivation Function (KDF) 및 Password Hashing algorithm의 unit test 및 표준 RFC Test Vector 검증 module (`kdf/`).
* **주요 기능**:
  * **HKDF Engine Verification**: HMAC 기반 Extract-and-Expand Key Derivation Function 연산 검증 (`testcase_hkdf.cpp`).
  * **Standard RFC KDF Test Vector Parsing**: RFC 4615 (AES-CMAC PRF-128), RFC 5869 (HKDF), RFC 6070 (PBKDF2) 규격 검증 (`testvector_rfc4615.cpp`, `testvector_rfc5869.cpp`, `testcase_rfc6070.cpp`).
  * **Password Hashing & Memory-Hard Function Verification**: RFC 7914 (scrypt) 및 RFC 9106 (Argon2d/Argon2i/Argon2id) 연산 검증 (`testcase_rfc7914.cpp`, `testcase_rfc9106.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **KDF & Password Hashing Testcases (`testcase_*.cpp`)**:
  * **HKDF**: OpenSSL/내부 구현 기반 Extract 및 Expand 연산의 단계별 동작 확인 (`testcase_hkdf.cpp`).
  * **PBKDF2 (RFC 6070)**: Iteration count 증가에 따른 HMAC-SHA1 기반 Key Derivation 연산 검증 (`testcase_rfc6070.cpp`).
  * **scrypt (RFC 7914) & Argon2 (RFC 9106)**: Memory-hard parameter (Cost factor, Block size, Parallelization) 적용 시 Hash 연산 정성 검증 (`testcase_rfc7914.cpp`, `testcase_rfc9106.cpp`).
* **Test Vector Engine (`testvector_*.cpp`, `*.yml`)**:
  * **RFC 4615**: AES-CMAC-PRF-128 기반 Variable Key Size 처리 연산 검증 (`testvector_rfc4615.cpp`).
  * **RFC 5869**: SHA-1 및 SHA-256 HKDF 표준 Test Vector YAML parsing 및 comparison 검증 (`testvector_rfc5869.cpp`).

---

### 3. 핵심 동작 mechanism

* **KDF Verification Flow (`testvector_*.cpp`, `testcase_*.cpp`)**:
  * YAML/RFC Known Input (IKM, Salt, Info, Cost Parameters 등) load -> HKDF / PBKDF2 / scrypt / Argon2 Key Derivation 연산 수행 -> Derived Key가 Known Output과 일치하는지 byte-by-byte comparison 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `testcase_rfc9106.cpp` 내 Argon2 Memory Allocation 실패 시 Boundary Check 및 Safe Free 연산 검증 | High | 미진행 |
| **#2** | `testcase_rfc7914.cpp` 내 scrypt Large Cost Factor ($N$) 설정 시 Stack/Heap Exhaustion 방지 예외 처리 | High | 미진행 |
| **#3** | `testvector_rfc5869.cpp` 내 HKDF Expand phase 의 Maximum Output Length ($255 \times \text{HashLen}$) 초과 시 Validation 강화 | Medium | 미진행 |
| **#4** | `testcase_rfc6070.cpp` 내 PBKDF2 High Iteration Count 연산 시 CPU Spiking 완화 방안 검토 | Low | 미진행 |
