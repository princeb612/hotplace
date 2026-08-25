## OpenSSL 기반 키 생성 module (`crypto_keygen`) 분석 - published by Gemini

---

### 1. 개요 및 핵심 개념

* **module 역할**: 다양한 비대칭키(RSA, EC, OKP, DH, DSA) 및 대칭키(OCT), OpenSSL 3.x 기반 PQC/최신 algorithm(ML-KEM, ML-DSA 등)의 키 생성과 encoding/decoding 추상화 제공.
* **C++11 및 설계 특징**:
  * builder pattern(Fluent Interface) style 지원 (`set().build()` / `gen()`).
  * OpenSSL 3.0+ API (`OSSL_ENCODER`, `OSSL_DECODER`, `EVP_PKEY_fromdata`) 및 pipeline(`function_pipeline`) module을 활용한 처리 구조 적용.
  * `critical_section_guard`를 통한 thread 안전성 확보.

---

### 2. 주요 class 및 핵심 method

```cpp
namespace hotplace {
namespace crypto {

class crypto_keygen {
   public:
    crypto_keygen(crypto_key* key, const std::string& kty, encoding_t encoding = {});

    // Builder interfaces
    crypto_keygen& set(keydesc&& desc);
    crypto_keygen& set(crypt_item_t item, binary_t&& value);
    crypto_keygen& set(const char* item, binary_t&& value);
    crypto_keygen& gen();    // 난수 기반 키 생성
    crypto_keygen& build();  // parameter(x, y, d 등) 기반 키 조립

    // OpenSSL 3.x Provider & Encoder/Decoder APIs
    static return_t pkey_keygen_byname(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const char* name);
    static return_t pkey_encode_format(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);
    static return_t pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding, const char* passphrase = nullptr);
    static return_t pkey_encode_raw(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding);
    static return_t pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding);
    static bool pkey_is_private(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey);

    // Dynamic Key Adding Helpers
    static return_t add_oct(crypto_key* cryptokey, size_t size, keydesc&& desc);
    static return_t add_ec(crypto_key* cryptokey, uint32 nid, keydesc&& desc);
    static return_t add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, keydesc&& desc);
    static return_t add_ossl3(crypto_key* cryptokey, const char* name, keydesc&& desc);
};

}  // namespace crypto
}  // namespace hotplace

```

---

### 3. 주요 구현 흐름

* **encoding 및 빌드 (`build`)**:
  * `set()`으로 수집된 문자열/바이트 파라미터를 지정된 `encoding_t`(Base16/Base64/Base64Url 등)에 맞춰 decoding 수행.
  * `kty`(Key Type: EC, RSA, OKP, DH 등)에 따라 적절한 `crypto_keychain::add_*` method를 분기 호출.
* **OpenSSL 3.x decoding/RAW 처리 (`pkey_decode`, `pkey_decode_raw`)**:
  * PEM/DER 형식인 경우 `OSSL_DECODER_CTX` 구조체를 사용하여 decoding 처리.
  * RAW Key인 경우 `OSSL_PARAM` parameter 구조체 구성 후 `EVP_PKEY_fromdata`를 통해 `EVP_PKEY` 객체 복원.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | ML-KEM, ML-DSA, SLH-DSA algorithm의 `build()` 연동 내부 구현 추가 | High | 진행 중 |
| **#2** | OpenSSL 3.x 미만 환경(`OPENSSL_VERSION_NUMBER < 0x30000000L`) 예외 처리 검증 | High | 완료 |
| **#3** | RAW 비밀키/공개키 encoding(`pkey_encode_raw`) 시 algorithm별 buffer 크기 유효성 검사 강화 | Medium | 미진행 |
| **#4** | `crypto_keygen` class 단위 test case 추가 (P-256, X25519, RSA-PSS 등) | Low | 미진행 |
