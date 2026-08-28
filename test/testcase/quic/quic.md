# QUIC / HTTP/3 - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A module supporting the QUIC (RFC 9000, RFC 9369) transport protocol, QUIC-based TLS 1.3 packet protection (RFC 9001), and HTTP/3 operations.
* **Key Features**:
  * **QUIC Packet Parsing and Building**: Initial, Handshake, 0-RTT, and 1-RTT packet framing operations.
  * **TLS 1.3 / QUIC Crypto Binding**: QUIC-specific TLS 1.3 Key Schedule derivation and Header Protection operations (`testcase_rfc9001.cpp`).
  * **Standard RFC Test Vector Verification**: Verification of RFC 9000 core, RFC 9001 security, and RFC 9369 v2 protocol version compatibility.
  * **HTTP/3 and PCAP Verification**: Parsing of captured HTTP/3 traffic YML test vectors and unit testing (`testvector_pcap_http3.yml`).

---

### 2. Core Implementation Areas and Technical Elements by Protocol

* **QUIC Core Frame Control (`testcase_rfc9000.cpp`, `testcase_construct_quic.cpp`)**:
  * Variable-Length Integer (VLI) encoding/decoding as well as ACK, STREAM, and CRYPTO frame assembly.
  * Connection ID parsing and packet structure processing.
* **QUIC Packet Protection and Header Encryption (`testcase_rfc9001.cpp`)**:
  * QUIC v1/v2 secret derivation and Header Protection Mask operations.
  * PN (Packet Number) decoding and AEAD encryption/decryption operations.
* **1-RTT Data Transmission and DTLS/QUIC Extensions (`testcase_construct_1rtt.cpp`, `testcase_rfc9369.cpp`)**:
  * 1-RTT Application Data packet generation operations following handshake completion.
  * QUIC v2 (RFC 9369) modifications and Version Negotiation compatibility verification.
* **HTTP/3 and Packet Traffic Debugging (`testvector_pcap_http3.yml`, `testvector_pcap.cpp`)**:
  * QPACK encoding and HTTP/3 frame traffic parsing analysis.
  * Provides a verification interface comparing operations against YML-based PCAP dump data.

---

### 3. Core Operating Mechanism

* **QUIC Handshake & CRYPTO Frame Construction (`testcase_quic.cpp`)**:
  * Encapsulates and transmits TLS 1.3 handshake messages into QUIC CRYPTO frames.
* **Header Protection & Packet Protection (`testcase_rfc9001.cpp`)**:
  * Extracts sample data, generates a Header Mask using AES-ECB / ChaCha20 operations, and decrypts the PN.
* **RFC 9369 QUIC v2 Compatibility Verification (`testcase_rfc9369.cpp`)**:
  * Verifies differences between QUIC v1 and v2 packet types, Header Formats, and key derivation salt values.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-QUIC-01** | Strengthen exception handling for Header Protection Mask generation and PN decoding in `testcase_rfc9001.cpp`<br> | High | Open |
| **TODO-QUIC-02** | Validate Short Header packet AEAD decryption based on `testcase_construct_1rtt.cpp`<br> | High | Open |
| **TODO-QUIC-03** | Implement v1/v2 switching and Version Negotiation handling when applying QUIC v2 Salt in `testcase_rfc9369.cpp`<br> | Medium | Open |
| **TODO-QUIC-04** | Improve exception handling for QPACK decoder stream errors using `testvector_pcap_http3.yml` data | Medium | Open |
| **TODO-QUIC-05** | Add overflow test cases for Variable-Length Integer encoding boundary values | Low | Open |
