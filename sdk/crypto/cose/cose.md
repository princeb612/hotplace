## COSE (CBOR Object Signing and Encryption) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 8152 / RFC 9052 (COSE) 표준 규격을 준수하여 CBOR 데이터 구조 기반의 암호화, 서명, MAC(message 인증 code) 및 키 관리를 수행하는 C++11 library module.
* **주요 기능**:
  * **COSE message 구조 처리**: Protected/Unprotected Header (`cose_protected`, `cose_unprotected`), Payload, Recipient (`cose_recipient`, `cose_recipients`), Countersign (`cose_countersign`, `cose_countersigns`) 등의 parameter 구조체 지원.
  * **암호화 / 서명 / MAC 연산**: `cbor_object_encryption`(COSE_Encrypt/COSE_Encrypt0), `cbor_object_signing`(COSE_Sign/COSE_Sign1) 및 MAC 기반 객체 연산 지원.
  * **다중 layer 및 builder 구조**: `cose_composer` builder pattern 및 서명/암호화 중첩 연산(`cbor_object_signing_encryption_*`) 제공.
  * **COSE Key 관리**: `cose_key` 및 `cbor_web_key` module을 통한 COSE Key / COSE Key Set 데이터 parsing 및 mapping.
* **C++11 특징**:
  * builder pattern 기반 chaining interface 구현 및 `std::vector<uint8_t>` 중심의 binary buffer 제어.
  * 공통 데이터 타입 및 상수 추상화를 위한 `types.hpp` 활용.

---

### 2. 주요 class 및 API 구조

**COSE core 객체 및 message 구성 요소**

```cpp
namespace hotplace {

// COSE 키 및 Header 관리
class cose_key;
class cbor_web_key;
class cose_protected;
class cose_unprotected;

// 수신자 및 이중 서명 구조체
class cose_recipient;
class cose_recipients;
class cose_countersign;
class cose_countersigns;

// COSE message builder
class cose_composer;

// COSE 암호화 / 서명 / MAC 연산 class
class cbor_object_encryption;
class cbor_object_signing;
class cbor_object_signing_encryption;

}  // namespace hotplace
```
[cite: 51]

---

### 3. 핵심 동작 mechanism

* **message 조립 (`cose_composer`)**:
  * Protected/Unprotected header 속성을 설정하고 Payload 데이터와 Recipient/Countersign 객체를 결합하여 최종 CBOR encoding된 COSE message 구조를 생성[cite: 51].
* **인증 및 암호화 연산 (`cbor_object_signing_encryption_*`)**:
  * 암호화(`_crypt`), 서명(`_sign`), MAC(`_mac`) 처리 module이 분리되어 있어, COSE 사양에 따른 Sign1/Encrypt0 단일 layer 구조부터 다중 Recipient를 포함하는 복합 구조까지 유연하게 구성[cite: 51].
* **header 및 수신자 관리 (`cose_protected`, `cose_recipient`)**:
  * Protected header는 무결성 검증 대상(CBOR bstr encoding)으로 처리되며, `cose_recipients`는 각 수신자별 키 분배(Key Transport/Key Agreement) parameter를 계층적으로 유지[cite: 51].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **TODO-COSE-01** | `cbor_object_encryption` 내 AES-CCM 및 AES-GCM algorithm 처리 시 Nonce/IV 크기 검증 강화 | High | 미진행 |
| **TODO-COSE-02** | `cose_countersign` 사양(RFC 9052) 기반의 Countersign V2 구조 호환성 검증 및 예외 처리 logic 구현 | High | 미진행 |
| **TODO-COSE-03** | `cose_composer` builder 내 header parameter 중복 설정 방지 및 유효성 검사 logic 추가 | Medium | 미진행 |
| **TODO-COSE-04** | `cose_key` parsing 시 OKP(Ed25519/X25519) 곡선 키 mapping 확장 및 validation 강화 | Medium | 미진행 |
