# TLS / DTLS - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A transport layer security protocol parsing and generation module covering TLS 1.2, TLS 1.3, DTLS 1.2, DTLS 1.3, and Post-Quantum (PQ) algorithms (ML-KEM).
* **Key Features**:
  * **TLS/DTLS Record & Handshake Control**: Record packet parsing, DTLS 1.2/1.3 handshake reassembly (`testcase_dtls_record_arrange.cpp`), and Alert handling.
  * **Standard Test Vector and RFC 8448 Verification**: RFC 8448 handshake test cases (`testcase_rfc8448_2.cpp` to `7.cpp`) and PCAP-based traffic verification support.
  * **Encryption and Post-Quantum (PQ) Extensions**: AEAD operations (`testcase_tls12_aead.cpp`), Pre-Master Secret calculation, and ML-KEM encoding (`testcase_mlkem_encoding.cpp`) parser support.
  * **ClientHello and HelloRetryRequest Handling**: ClientHello dumping (`dump_clienthello.cpp`) and HelloRetryRequest generation/verification (`testcase_helloretryrequest.cpp`).

---

### 2. Core Implementation Areas and Technical Elements by Protocol

* **TLS 1.3 Key Derivation and State Transitions (`testcase_understand_tls13.cpp`, `testcase_rfc8448_*.cpp`)**:
  * Verification of secret derivation (Early, Handshake, Master Secret) operations based on the Handshake Context transcript hash from ClientHello to Finished stages.
  * Implementation accuracy verification for the handshake key schedule via 1:1 comparison against RFC 8448 standard test vectors.
* **DTLS 1.2/1.3 Reliability Mechanism (`testcase_dtls_record_arrange.cpp`, `testcase_understand_dtls.cpp`)**:
  * Epoch / Sequence Number-based record reordering and fragmentation reassembly logic to compensate for unreliable UDP transport characteristics.
  * ACK frame and retransmission timer state management aligned with the DTLS 1.3 specification.
* **Post-Quantum Cryptography (PQC) Extension and AEAD Processing (`testcase_mlkem_encoding.cpp`, `testcase_tls12_aead.cpp`)**:
  * ML-KEM (Kyber)-based KeyShare extension encoding/decoding and TLS 1.3 binding parsing.
  * Explicit/Implicit Nonce construction and Additional Authenticated Data (AAD) calculations for AEAD ciphers like AES-GCM and ChaCha20-Poly1305.
* **Handshake Exception Control and Debugging (`testcase_helloretryrequest.cpp`, `dump_clienthello.cpp`)**:
  * KeyShare swap operations when receiving a HelloRetryRequest (HRR) in unsupported group scenarios.
  * A debugging interface that parses ClientHello payloads from binary streams to analyze extension lists and ciphersuite information.

---

### 3. Core Operating Mechanism

* **TLS/DTLS Record and Handshake Construction (`testcase_construct_*.cpp`)**:
  * Uses C++11 structures to build and encode TLS and DTLS 1.2/1.3 record layers and Handshake message structures.
* **DTLS Fragmentation and Reassembly (`testcase_dtls_record_arrange.cpp`)**:
  * Sequence Number-based fragmentation and reordering handling to accommodate unreliable UDP transport.
* **RFC 8448 & ML-KEM Verification (`testcase_rfc8448_*.cpp`, `testcase_mlkem_encoding.cpp`)**:
  * Test vector-based secret derivation for TLS 1.3 standard validation and next-generation post-quantum encryption (ML-KEM) encoding tests.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-TLS-01** | Validate ML-KEM key exchange and TLS 1.3 KeyShare extension parsing in `testcase_mlkem_encoding.cpp`<br> | High | Open |
| **TODO-TLS-02** | Verify retransmission timer logic during DTLS 1.3 handshake packet loss based on `testcase_dtls_record_arrange.cpp`<br> | High | Open |
| **TODO-TLS-03** | Supplement exception handling for AES-GCM and ChaCha20-Poly1305 AEAD tag verification in `testcase_tls12_aead.cpp`<br> | Medium | Open |
| **TODO-TLS-04** | Verify KeyShare re-request and Handshake Context update logic during HRR response in `testcase_helloretryrequest.cpp`<br> | Medium | Open |
| **TODO-TLS-05** | Refine unrecognized extension debugging log output in `dump_clienthello.cpp` parser | Low | Open |
