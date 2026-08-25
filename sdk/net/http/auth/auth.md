## HTTP Authentication & OAuth2 module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: RFC 2617 (Basic/Digest), Bearer token 및 OAuth2 protocol 기반 인증/인가 mechanism 제공 module.
* **주요 기능**:
  * **Basic Authentication**: Base64 기반 Credentials parsing 및 Provider 검증 (`basic_authentication_provider.cpp`, `basic_credentials.cpp`).
  * **Bearer Authentication**: OAuth2 / JWT Access Token 기반 Bearer 인증 처리 (`bearer_authentication_provider.cpp`, `bearer_credentials.cpp`).
  * **Digest Access Authentication**: RFC 2617 규격 기반 Nonce, Response Hash 연산 및 Digest 인증 제어 (`digest_access_authentication_provider.cpp`, `digest_credentials.cpp`, `rfc2617_digest.cpp`).
  * **OAuth2 Framework**: OAuth2 Grant Type 및 Access Token 발행/관리 연산 (`oauth2.cpp`, `oauth2_credentials.cpp`).
  * **Custom Credentials**: 사용자 정의 확장 인증 구조 지원 (`custom_credentials.cpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Basic & Bearer Credentials Handling (`basic_credentials.cpp`, `bearer_credentials.cpp`)**:
  * `Authorization` header encoding parsing 연산 및 사용자 Credentials 추출.
* **Digest Access Authentication & RFC 2617 Algorithm (`digest_access_authentication_provider.cpp`, `rfc2617_digest.cpp`)**:
  * Nonce, Opaque, Realm, QOP(Quality of Protection) parsing 연산 및 MD5/SHA256 Response Digest 계산 수행.
* **OAuth2 Protocol Implementation (`oauth2.cpp`, `oauth2_credentials.cpp`)**:
  * Client Credentials, Authorization Code 등 OAuth2 flow 구현 및 Access/Refresh Token lifecycle 관리.

---

### 3. 핵심 동작 mechanism

* **Digest Response Verification Flow (`digest_access_authentication_provider.cpp`)**:
  * 수신된 `Authorization: Digest ...` header parsing -> `rfc2617_digest` 함수 호출 -> HA1, HA2, Response Digest 연산 수행 후 client 송신 값과 비교 검증.
* **OAuth2 Token Validation Flow (`oauth2.cpp`)**:
  * Request Token 포함 여부 검사 -> Token Expiry 및 Scope verification 연산 -> 유효한 session 승인 처리.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `digest_access_authentication_provider.cpp` 내 Stale Nonce 처리 및 Nonce Replay Attack 방지 logic 보완 | High | 미진행 |
| **#2** | `oauth2.cpp` 내 Token Expiry 시간 계산 시 System Clock desync 예외 처리 강화 | High | 미진행 |
| **#3** | `rfc2617_digest.cpp` 내 MD5 외 SHA-256 Digest Algorithm 지원 검증 | Medium | 미진행 |
| **#4** | `basic_credentials.cpp` 내 Base64 decoding 시 Invalid Format 문자열 Input validation 강화 | Medium | 미진행 |
| **#5** | `custom_credentials.cpp` 내 Multi-tenant 환경 커스텀 header parsing 확장성 확인 | Low | 미진행 |
