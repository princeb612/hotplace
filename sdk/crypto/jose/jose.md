## JOSE (JSON Object Signing and Encryption) - published by Gemini

### 1. 개요 및 주요 특징

* **module 역할**: RFC 7515(JWS), RFC 7516(JWE), RFC 7517(JWK) 등 JOSE 표준 사양을 구현하여 JSON 데이터의 암호화, 서명, 키 관리를 처리하는 C++11 library module.
* **주요 기능**:
  * **JWE (JSON Object Encryption)**: `json_object_encryption` 및 builder 형태의 `json_object_encryption_composer`를 통해 JSON 데이터 암호화 지원.
  * **JWS (JSON Object Signing)**: `json_object_signing` 및 `json_object_signing_composer`를 활용하여 JSON message 무결성 검증 및 서명 제공.
  * **JWS + JWE 결합**: `json_object_signing_encryption`을 통해 서명 후 암호화(Sign-then-Encrypt) 중첩 처리 지원.
  * **JWK 및 서명 관리**: `json_web_key` 및 `json_web_signature` class로 암호화 키 세트 및 전자서명 객체 추상화.
* **C++11 특징**:
  * Builder/Composer pattern을 활용한 method chaining interface 구현.
  * 내부 buffer 관리에 `std::vector<uint8_t>`, `std::string` 활용 및 타입 안전성을 위한 `types.hpp` 정의.

---

### 2. 주요 class 및 API 구조

**JOSE core 객체 및 builder 구조**

```cpp
namespace hotplace {

// JWK (JSON Web Key) 및 서명 관리
class json_web_key;
class json_web_signature;

// JWE 암호화 처리 class 및 builder
class json_object_encryption;
class json_object_encryption_composer;

// JWS 서명 처리 class 및 builder
class json_object_signing;
class json_object_signing_composer;

// JWS + JWE 서명 및 암호화 연동 class
class json_object_signing_encryption;

}  // namespace hotplace
```
[cite: 50]

---

### 3. 핵심 동작 mechanism

* **JWS/JWE Composer (builder pattern)**:
  * `json_object_signing_composer` 및 `json_object_encryption_composer`: header(Algorithm, Enc, Kid 등) 설정, Payload 지정, 키 연결을 단계별로 조립하여 최종 Compact/JSON Serialization 형태로 encoding[cite: 50].
* **Sign-then-Encrypt (`json_object_signing_encryption`)**:
  * 원본 데이터에 대해 JWS 서명을 먼저 수행한 후, 생성된 JWS 결과를 JWE payload로 전달하여 암호화 계층을 중첩 처리[cite: 50].
* **키 및 서명 검증 (`json_web_key`, `json_web_signature`)**:
  * `json_web_key`를 통해 RSA/ECC/Symmetric 키 구조를 표준 JWK 포맷과 상호 변환하고, `json_web_signature`로 서명 검증을 수행[cite: 50].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **TODO-JOSE-01** | `json_object_encryption`에서 AES-GCM 및 ChaCha20-Poly1305 등 AEAD 암호화 tag 검증 logic 정밀화 | High | 미진행 |
| **TODO-JOSE-02** | `json_web_key` parsing 시 지원되지 않는 algorithm(alg) 또는 키 타입(kty) 예외 처리 logic 강화 | High | 미진행 |
| **TODO-JOSE-03** | `json_object_signing_composer` 및 `encryption_composer` 메모리 복사 최소화를 위한 Rvalue Reference/Move 세터 추가 | Medium | 미진행 |
| **TODO-JOSE-04** | JWK 키 세트(JWKS) 다중 키 검색 및 `kid` 기반 키 matching 성능 향상 algorithm 개선 | Low | 미진행 |
