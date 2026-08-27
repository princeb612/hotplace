## SSLKEYLOGFILE - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: TLS 1.2, TLS 1.3, DTLS 및 QUIC (QUICv1, QUICv2) protocol 통신 과정에서 암호화 key schedule 정보를 외부로 추출/주입하는 keylog 제어 module
* **주요 기능**:
  * **Keylog Export 및 Callback 연동 (`sslkeylog_exporter`)**: TLS 1.2 master secret, TLS 1.3/QUIC traffic secret 계산 시점에 SSLKEYLOGFILE 규격의 텍스트 생성 및 사용자 정의 callback 함수 연동.
  * **Keylog Import 및 Session Binding (`sslkeylog_importer`)**: 외부 SSLKEYLOGFILE 텍스트 릴레이를 파싱하여 `tls_session` 객체에 secret 데이터를 수동 주입하고 암호화 세션 복호화 지원.

---

### 2. protocol별 핵심 구현 영역 및 기술 요소

* **SSLKEYLOG Export 연동 (`sslkeylog_exporter.hpp`, `tls_protection_calc.cpp`)**:
  * `tls_protection::calc` 키 파생 단계에서 Singleton 객체를 통해 `CLIENT_RANDOM`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_TRAFFIC_SECRET_0` 등의 keylog 텍스트를 자동 생성.
  * `set_tls_keylog_callback()`을 통해 외부 logger 및 Wireshark 연동용 stream hook 지정 가능.
* **SSLKEYLOG Import 및 Session 매핑 (`sslkeylog_importer.hpp`)**:
  * `operator<<` 텍스트 스트림 입력 방식을 지원하여 `CLIENT_RANDOM` 바이너리 키 기반으로 세션별 `tls_secret_t` 매핑 데이터 구축.
  * `attach()` 메서드로 `tls_session` 상태 변화 이벤트(`session_status_changed`)를 감지하고 secret 동기화 유지.

---

### 3. 핵심 동작 mechanism

* **TLS Key Schedule 연동 키 추출 (`sslkeylog_exporter::log`)**:
  * ClientHello/ServerHello/Finished 단계 처리 시 `tls_protection::calc` 내부에서 `sslkeylog_exporter::get_instance()->log()`를 호출하여 real-time secret 추출 연산 수행.
* **Secret 주입 및 Session 복호화 연동 (`sslkeylog_importer::attach`)**:
  * 미리 파싱된 secret_map 데이터를 기반으로 대상 `tls_session` 세션에서 pre-master secret 대신 전달받은 keylog 값을 직접 채택하도록 설정.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 | 비고 |
| --- | --- | --- | --- | --- |
| **TODO-SKL-01** | `sslkeylog_importer.hpp` 내 SSLKEYLOGFILE 텍스트 파일 경로 입력 기반 자동 파싱/로딩 `load_file()` API 구현 | High | 미진행 | `sslkeylog_importer.hpp`<br> |
| **TODO-SKL-02** | `tls_protection_calc.cpp` 연동 QUIC / QUICv2 Initial Secret Keylog Exporter/Importer 동작 유효성 검증 | Medium | 진행 중 | `tls_protection_calc.cpp`<br> |
| **TODO-SKL-03** | 다중 스레드 환경에서 `sslkeylog_exporter::log()` 동시 호출 시 race condition 방지를 위한 critical section 검토 | Low | 미진행 | `sslkeylog_exporter.hpp`<br> |
