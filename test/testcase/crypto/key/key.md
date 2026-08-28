# Key - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A unit test suite and test vector verification module for cryptographic key generation, asymmetric key algorithms (RSA, DSA, EC, DH, FFDHE, HPKE, ML-KEM), DER encoding, and key exchange verification (`key/`).
* **Key Features**:
  * **Asymmetric & Post-Quantum Key Testing**: Executes test cases for RSA, DSA, EC, DH, FFDHE, and post-quantum cryptography (ML-KEM, HPKE) (`testcase_key_rsa.cpp`, `testcase_key_mlkem.cpp`, `testcase_hpke.cpp`, etc.).
  * **Key Generation & Key Exchange Verification**: Verifies the correctness of key generation operations and DH/ECDH key exchanges (`testcase_keygen.cpp`, `testcase_keyexchange.cpp`).
  * **Test Vector Validation**: Loads, parses, and verifies external YAML-based test vectors, including RFC 7919 FFDHE (`testvector_keygen.cpp`, `testvector_keyshare.cpp`, `testvector_rfc7919.cpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **Algorithm Specific Testcases (`testcase_*.cpp`)**:
  * **RSA / DSA / EC / DH / FFDHE**: Tests asymmetric key generation, parameter validation, and DER encoding/decoding operations (`testcase_der.cpp`, `testcase_curves.cpp`).
  * **HPKE / ML-KEM**: Verifies C++11-based Hybrid Public Key Encryption and PQC (Post-Quantum Cryptography) ML-KEM algorithms (`testcase_hpke.cpp`, `testcase_key_mlkem.cpp`).
* **Test Vector Engine (`testvector_*.cpp`, `*.yml`)**:
  * Parses Known Answer Test (KAT) data from YAML files (`testvector_keygen.yml`, `testvector_keyshare.yml`, `testvector_rfc7919.yml`) and executes comparison verification.

---

### 3. Core Operating Mechanism

* **Test Vector Execution Flow (`testvector_*.cpp`)**:
  * Loads and parses YAML test vectors $\rightarrow$ Injects known inputs (Seed, Private Key, etc.) $\rightarrow$ Performs Crypto Key Module operations $\rightarrow$ Executes byte-by-byte comparison operations to ensure results match known outputs (Public Key, Shared Secret).

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-CK-01** | Verify memory boundary safety and secret key leakage during PQC ML-KEM algorithm operations in `testcase_key_mlkem.cpp`<br> | High | Open |
| **TODO-CK-02** | Supplement exception handling during parsing of RFC 7919 FFDHE group parameters in `testvector_rfc7919.cpp`<br> | High | Open |
| **TODO-CK-03** | Write additional test cases for Single-shot and Export-only HPKE modes in `testcase_hpke.cpp`<br> | Medium | Open |
| **TODO-CK-04** | Strengthen validation against malformed YAML inputs during YAML deserialization in `testvector_keyshare.cpp`<br> | Low | Open |
