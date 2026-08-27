## OpenSSL 기반 TLS 키 교환 및 PQC/hybrid KEM module (`crypto_keyexchange`) 분석 - published by Gemini

---

### 1. 개요 및 핵심 개념

* **module 역할**: TLS 1.3 algorithm 규격 기반 ECDHE, ML-KEM 및 ECDHE-MLKEM hybrid 키 교환 mechanism을 추상화하여 제공.
* **C++11 및 설계 특징**:
  * OpenSSL 기반 PQC (ML-KEM) 및 ECDH algorithm 지원.
  * reference counting(`t_shared_reference`) 기반 resource/life-cycle 관리 (`addref`, `release`).
  * `__try2`, `__leave2`, `__finally2` macro 구조를 통한 단일 진출점 기반 error handling pattern 적용.
  * RFC/Draft 스펙에 정의된 hybrid 결합 방식(EC/OKP와 ML-KEM 순서 조합) 지원.

---

### 2. 주요 class 및 핵심 method

```cpp
namespace hotplace {
namespace crypto {

class crypto_keyexchange {
   public:
    crypto_keyexchange(tls_group_t group = tls_group_t{});
    ~crypto_keyexchange();

    // Key generation & Public share extraction
    return_t keygen(crypto_key* key, const char* kid, binary_t& share);

    // ECDHE Key exchange
    return_t exchange(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    // PQC / Hybrid ML-KEM Encapsulation & Decapsulation
    return_t encaps(const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret);
    return_t decaps(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    tls_group_t get_group() const;

    void addref();
    void release();
};

}  // namespace crypto
}  // namespace hotplace

```

---

### 3. 주요 구현 흐름

* **키 생성 (`keygen`)**:
  * `crypto_advisor`에서 지정된 `tls_group_t` hint 정보를 수집.
  * 단일 algorithm 또는 hybrid 조합(`tls_flag_hybrid`) 여부에 따라 키쌍을 생성 및 공개키(`share`) 바이트열 binding.
* **키 캡슐화 (`encaps`)**:
  * client의 공개키 `share` 수신 후 `keystore()`를 통해 임시 저장.
  * ML-KEM 캡슐화 수행(`pqc.encapsule`) 후 `keycapsule` 및 공유비밀키(`sharedsecret`) 도출.
  * hybrid 그룹인 경우 ECDH 키 합의 결과를 규격에 맞춰 직렬화 결합 (`secp256r1mlkem768`: EC || ML-KEM, `x25519mlkem768`: ML-KEM || X25519).
* **키 디캡슐화 (`decaps`)**:
  * 캡슐화 데이터 규격 검증 후 비밀키를 통한 `pqc.decapsule` 수행.
  * hybrid 연산 결과 조합을 거쳐 최종 `sharedsecret` 복원.
---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-KE-01** | ML-KEM draft-ietf-tls-ecdhe-mlkem 규격 변경에 따른 직렬화 순서 동기화 검증 | High | 진행 중 |
| **TODO-KE-02** | `crypto_keyexchange` 내 멀티thread reference counting thread 안정성(Thread-safety) test case 추가 | High | 미진행 |
| **TODO-KE-03** | 지원되지 않는 `tls_group_t` 진입 시 error 로그 생성 및 세부 반환 code 정의 | Medium | 미진행 |
| **TODO-KE-04** | OpenSSL 3.x PQC provider loading 성능 최적화 및 벤치마크 테스트 구현 | Low | 미진행 |
