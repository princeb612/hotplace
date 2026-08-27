## CBC-HMAC 조합형 AEAD 처리 module (`crypto_cbc_hmac`) 분석 - published by Gemini

---

### 1. 개요 및 핵심 개념

* **module 역할**: AES-CBC 대칭 암호화와 HMAC 인증을 결합한 AEAD(Authenticated Encryption with Associated Data) 처리 module.
* **지원 사양 및 mechanism**:
  * **JOSE (EtM)**: RFC 7516 기반의 Encrypt-then-MAC 방식. Tag를 별도 변수(`separated tag`)로 분리 반환.
  * **TLS MtE**: TLS 1.2 표준의 Mac-then-Encrypt 방식 (`nested tag`).
  * **TLS EtM**: RFC 7366 확장 표준의 Encrypt-then-MAC 방식 (`concatenated tag`).
* **C++11 및 설계 특징**:
  * `t_shared_reference`를 이용한 reference counting 기반 메모리 관리 (`addref`, `release`).
  * `__try2`, `__leave2`, `__finally2` macro 구문을 활용한 예외 및 자원 해제 제어.
  * Fluent Interface style의 algorithm/flag 설정 (`set_enc().set_mac().set_flag()`).

---

### 2. 주요 class 및 method 구성

```cpp
namespace hotplace {
namespace crypto {

class crypto_cbc_hmac {
   public:
    crypto_cbc_hmac();

    // Configuration interfaces (Fluent)
    crypto_cbc_hmac& set_enc(crypt_algorithm_t enc_alg);
    crypto_cbc_hmac& set_mac(hash_algorithm_t mac_alg);
    crypto_cbc_hmac& set_flag(uint16 flag);  // jose_encrypt_then_mac, tls_mac_then_encrypt, tls_encrypt_then_mac

    // Key Splitting Helper (Key = MAC_KEY || ENC_KEY)
    return_t split_key(const binary_t key, binary_t& enckey, binary_t& mackey) const;

    // Concatenated / Nested Tag (TLS mode)
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext, binary_t& ciphertext) const;
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext) const;

    // Separated Tag (JOSE mode)
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext, binary_t& ciphertext, binary_t& tag) const;
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext, const binary_t& tag) const;

    void addref();
    void release();
};

}  // namespace crypto
}  // namespace hotplace

```

---

### 3. 동작 방식 및 flag별 처리 흐름

* **`split_key` (키 분할)**:
  * 입력받은 마스터 키 `key`에서 상위 바이트는 MAC 키로, 하위 바이트는 암호화 키(ENC 키)로 분할.
  * JOSE 규격에 따라 HMAC Digest 크기를 절반으로 절단(truncate)하여 사용.
* **TLS 모드 (`encrypt` / `decrypt` overloading 1)**:
  * **`tls_mac_then_encrypt`**: 평문과 AAD 기반 HMAC Tag 생성 후 padding과 함께 CBC 암호화 수행.
  * **`tls_encrypt_then_mac`**: CBC 암호화 수행 후, 암호문과 AAD 기반 HMAC Tag를 계산하여 `ciphertext || tag` 형태로 결합.
* **JOSE 모드 (`encrypt` / `decrypt` overloading 2)**:
  * **`jose_encrypt_then_mac`**: CBC 암호문 `Q` 생성 후 $MAC(MAC\_KEY, AAD \mid\mid IV \mid\mid Q \mid\mid AL)$ 공식으로 Tag 생성 및 Truncate.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-CBCHMAC-01** | JOSE 모드 HMAC Tag 연산 시 Constant-time 비교 함수 적용 (Timing Attack 방지) | High | 미진행 |
| **TODO-CBCHMAC-02** | `tls_mac_then_encrypt` 복호화 시 padding 검증 및 오류 처리 logic 보강 (Lucky Thirteen 공격 대비) | High | 미진행 |
| **TODO-CBCHMAC-03** | `split_key` 단위 테스트 및 JWE A128CBC-HS256 벡터 검증 케이스 추가 | Medium | 진행 중 |
| **TODO-CBCHMAC-04** | C++11 `std::shared_ptr` 기반 내부 참조 관리 refactoring 검토 | Low | 미진행 |
