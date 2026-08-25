## Key Engine Test Suite & Test Vectors - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 암호화 키 생성, 비대칭키 algorithm(RSA, DSA, EC, DH, FFDHE, HPKE, ML-KEM), DER encoding 및 Key Exchange 검증을 위한 unit test suite 및 test vector 검증 module (`key/`).
* **주요 기능**:
  * **Asymmetric & Post-Quantum Key Testing**: RSA, DSA, EC, DH, FFDHE 및 post-quantum cryptography ML-KEM, HPKE test case 수행 (`testcase_key_rsa.cpp`, `testcase_key_mlkem.cpp`, `testcase_hpke.cpp` 등).
  * **Key Generation & Key Exchange Verification**: 키 생성 연산 및 DH/ECDH Key Exchange 올바름 검증 (`testcase_keygen.cpp`, `testcase_keyexchange.cpp`).
  * **Test Vector Validation**: YAML 규격 기반 외부 test vector (RFC 7919 FFDHE 등) load 및 parsing 검증 (`testvector_keygen.cpp`, `testvector_keyshare.cpp`, `testvector_rfc7919.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Algorithm Specific Testcases (`testcase_*.cpp`)**:
  * **RSA / DSA / EC / DH / FFDHE**: 비대칭 키 생성, parameter 유효성 검증 및 DER encoding/decoding 연산 테스트 (`testcase_der.cpp`, `testcase_curves.cpp`).
  * **HPKE / ML-KEM**: C++11 기반 Hybrid Public Key Encryption 및 PQC (Post-Quantum Cryptography) ML-KEM algorithm 검증 (`testcase_hpke.cpp`, `testcase_key_mlkem.cpp`).
* **Test Vector Engine (`testvector_*.cpp`, `*.yml`)**:
  * YAML 파일 (`testvector_keygen.yml`, `testvector_keyshare.yml`, `testvector_rfc7919.yml`) 기반 Known Answer Test (KAT) 데이터 parsing 및 연산 비교 검증.

---

### 3. 핵심 동작 mechanism

* **Test Vector Execution Flow (`testvector_*.cpp`)**:
  * YAML test vector load 및 parsing -> Known input (Seed, Private Key 등) 주입 -> Crypto Key Module 연산 수행 -> Known output (Public Key, Shared Secret) 과 결과 byte-by-byte comparison 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `testcase_key_mlkem.cpp` 내 PQC ML-KEM algorithm 연산 시 memory boundary 및 secret key leakage 검증 | High | 미진행 |
| **#2** | `testvector_rfc7919.cpp` 내 RFC 7919 FFDHE group parameters parsing 연산 예외 처리 보완 | High | 미진행 |
| **#3** | `testcase_hpke.cpp` 내 Single-shot 및 Export-only HPKE mode testcase 추가 작성 | Medium | 미진행 |
| **#4** | `testvector_keyshare.cpp` 내 YAML deserialization 시 malformed YAML input 에 대한 validation 강화 | Low | 미진행 |
