## Crypto Keychain module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: algorithm별 암호화 키 저장소 관리, OpenSSL 3.0 provider 연동 및 Key Exchange handling module.
* **주요 기능**:
  * **Algorithm Specific Keychains**: RSA, EC, DH, DSA, OCT, OKP algorithm별 키 저장 및 관리 연산 (`crypto_keychain_rsa.cpp`, `crypto_keychain_ec.cpp`, `crypto_keychain_dh.cpp` 등).
  * **EC Point Compression Formatting**: Elliptic Curve 압축/비압축 포맷 지원 (`crypto_keychain_ec_compressed.cpp`, `crypto_keychain_ec_uncompressed.cpp`).
  * **OpenSSL 3.0 Provider Abstraction**: OpenSSL 3.0 EVP_PKEY 연동 및 키 storage backend interface (`crypto_keychain_ossl3.cpp`).
  * **Key Exchange Operations**: DH/ECDH Key Agreement 및 shared secret 파생 연산 (`crypto_keyexchange.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Algorithm Keychain Implementations (`crypto_keychain_*.cpp`)**:
  * algorithm별(RSA, EC, DH, DSA, OCT, OKP) 키쌍 생성 및 store 관리.
* **EC Point Format Handling (`crypto_keychain_ec_compressed.cpp`, `crypto_keychain_ec_uncompressed.cpp`)**:
  * 타원곡선 좌표 압축/비압축 직렬화 연산 지원.
* **OpenSSL 3 Integration & Key Exchange (`crypto_keychain_ossl3.cpp`, `crypto_keyexchange.cpp`)**:
  * OpenSSL 3.0 Provider API backend 연동 및 Key Agreement 연산.

---

### 3. 핵심 동작 mechanism

* **Keychain Generation & Key Exchange Flow (`crypto_keychain.cpp`, `crypto_keyexchange.cpp`)**:
  * keychain 조회/생성 요청 -> algorithm provider(`crypto_keychain_ossl3`) 연동 -> 키쌍 할당 -> `crypto_keyexchange` pipeline을 통한 Shared Secret 파생 연산 수행.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `crypto_keychain_ossl3.cpp` 내 OpenSSL 3.0 EVP_PKEY context allocation 실패 시 error handling 보완 | High | 미진행 |
| **#2** | `crypto_keyexchange.cpp` 내 Shared Secret 계산 과정 메모리 leak 및 data race 검증 | High | 미진행 |
| **#3** | `crypto_keychain_ec_compressed.cpp` 내 EC point decompression 연산 시 invalid point validation 강화 | High | 미진행 |
| **#4** | `crypto_keychain_rsa.cpp` 내 key generation timing attack 방지 및 secure padding 적용 확인 | Medium | 미진행 |
| **#5** | `crypto_keychain_okp.cpp` 내 Ed25519 / X25519 key derivation performance profiling 검토 | Low | 미진행 |
