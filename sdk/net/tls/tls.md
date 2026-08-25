## TLS (Transport Layer Security) module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: TLS/DTLS protocol의 record layer, handshake mechanism, 확장(Extensions) 기능 및 암호화 보호(Protection) layer를 구현 및 parsing하는 핵심 module.
* **주요 기능**:
  * **TLS/DTLS record 관리**: `tls_record`, `dtls13_ciphertext` 및 다양한 record 타입(Handshake, Alert, Application Data, Change Cipher Spec 등) parsing/생성.
  * **handshake message 처리**: ClientHello, ServerHello, Certificate, CertificateVerify, Finished, NewSessionTicket 등 TLS Handshake message parsing 및 builder 구현.
  * **다양한 TLS Extension 지원**: SNI, ALPN, KeyShare, PreSharedKey, SupportedGroups, QUIC Transport Parameters 등 표준 확장 구현.
  * **보호 및 키 계산 (`tls_protection`)**: AEAD/CBC-HMAC 암호화, Keyblock/PSK 계산, Finished 검증 및 HP(Header Protection) 연산 수행.
  * **TLS Advisor & SSLKeyLog**: Ciphersuite 및 parameter mapping 정보(`tls_advisor`) 제공 및 SSLKeyLog Exporter/Importer 기능 지원.

---

### 2. 주요 class 및 module 구조

**TLS core module 구성**

```cpp
namespace hotplace {

// TLS session 및 어드바저
class tls_session;
class tls_advisor;

// TLS record 및 handshake builder/parser
class tls_record;
class tls_record_builder;
class tls_handshake;
class tls_handshake_builder;

// TLS 보호 및 암호화 layer
class tls_protection;
class tls_protection_context;

// SSLKeyLog 수출/입
class sslkeylog_exporter;
class sslkeylog_importer;

}  // namespace hotplace

```

---

### 3. 핵심 동작 mechanism

* **record & handshake builder 구조 (`tls_record_builder`, `tls_handshake_builder`)**:
  * 객체지향 builder pattern을 사용하여 TLS record packet 및 handshake payload를 동적으로 구성.
* **보호 layer 암호화 연산 (`tls_protection`)**:
  * handshake 단계별 단방향/양방향 암호화 키를 파생하고 AEAD(GCM/CCM) 또는 CBC-HMAC 방식을 적용하여 message 보호 처리.
* **DTLS 및 QUIC 연동 확장**:
  * `dtls_record_arrange`, `dtls_handshake_fragmented`를 통한 DTLS packet 재전송/단편화 처리.
  * `tls_extension_quic_transport_parameters`를 제공하여 TLS 1.3 기반 QUIC handshake parameter 교환 지원.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `tls_protection_encryption_aead` 내 TLS 1.3 Secret 파생 및 Key Update mechanism 예외 처리 검증 | High | 미진행 |
| **#2** | `tls_handshake_certificate_verify` 내 Ed25519 및 RSA-PSS 서명 검증 logic 단위 테스트 추가 | High | 미진행 |
| **#3** | `tls_extension_encrypted_client_hello` (ECH) 사양 변경에 따른 HPKE binding logic 정리 | Medium | 미진행 |
| **#4** | `dtls_record_arrange` module의 순서 어긋남(Out-of-order) 및 packet 손실 시 재조합 buffer링 최적화 | Medium | 미진행 |
| **#5** | `sslkeylog_exporter` 및 `sslkeylog_importer` 간 TLS 1.3 Early Secret / Handshake Secret logging 누락 방지 logic 추가 | Low | 미진행 |
