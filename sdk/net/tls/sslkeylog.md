Here is the translated document for the SSLKEYLOGFILE module in English:

---

## SSLKEYLOGFILE - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A keylog control module that extracts and injects encryption key schedule information during TLS 1.2, TLS 1.3, DTLS, and QUIC (QUICv1, QUICv2) protocol communications.
* **Key Features**:
  * **Keylog Export & Callback Integration (`sslkeylog_exporter`)**: Generates text in the SSLKEYLOGFILE format and triggers user-defined callback functions at the exact moment TLS 1.2 master secrets or TLS 1.3/QUIC traffic secrets are calculated.
  * **Keylog Import & Session Binding (`sslkeylog_importer`)**: Parses external SSLKEYLOGFILE text relays to manually inject secret data into `tls_session` objects, enabling decryption of encrypted sessions.

---

### 2. Protocol-Specific Implementation Areas and Technical Elements

* **SSLKEYLOG Export Integration (`sslkeylog_exporter.hpp`, `tls_protection_calc.cpp`)**:
  * Automatically generates keylog text entries such as `CLIENT_RANDOM`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, and `SERVER_TRAFFIC_SECRET_0` via a Singleton object during the `tls_protection::calc` key derivation phase.
  * Supports stream hook specification for external loggers and Wireshark integration via `set_tls_keylog_callback()`.
* **SSLKEYLOG Import & Session Mapping (`sslkeylog_importer.hpp`)**:
  * Supports `operator<<` text stream input to construct per-session `tls_secret_t` mapping data based on binary `CLIENT_RANDOM` keys.
  * Detects session status changes (`session_status_changed`) via the `attach()` method to maintain secret synchronization with `tls_session`.

---

### 3. Core Operating Mechanism

* **TLS Key Schedule Key Extraction (`sslkeylog_exporter::log`)**:
  * Calls `sslkeylog_exporter::get_instance()->log()` inside `tls_protection::calc` during ClientHello/ServerHello/Finished message processing to perform real-time secret extraction.
* **Secret Injection & Session Decryption Integration (`sslkeylog_importer::attach`)**:
  * Configures target `tls_session` instances to adopt keylog values received from pre-parsed secret map data instead of pre-master secrets.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-SKL-01** | Implement a `load_file()` API in `sslkeylog_importer.hpp` to enable automatic parsing and loading based on SSLKEYLOGFILE text file paths | High | Open | `sslkeylog_importer.hpp`<br> |
| **TODO-SKL-02** | Verify QUIC / QUICv2 Initial Secret Keylog Exporter/Importer behavior integrated with `tls_protection_calc.cpp`<br> | Medium | In Progress | `tls_protection_calc.cpp`<br> |
| **TODO-SKL-03** | Review critical section usage to prevent race conditions during concurrent `sslkeylog_exporter::log()` calls in multi-threaded environments | Low | Open | `sslkeylog_exporter.hpp`<br> |
