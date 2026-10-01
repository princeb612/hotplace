### TLS protection

- [TLS key schedule](tls_key_schedule.md)
- [MtE vs. EtM](tls_mte_etm.md)
- [Transcript Hash](tls_transcript_hash.md)

#### related tests

* `test/testcase/tls/testcase_tls12_aead.cpp`
* `test/testcase/tls/testcase_rfc8448_2.cpp`
* `test/testcase/tls/testcase_rfc8448_5.cpp`
* `test/testcase/tls/testcase_understand_tls12.cpp`

#### related areas

* `../session/` - handshake/session state
* `../quic/` - QUIC packet protection using TLS-derived secrets
* `sdk/crypto/` - HKDF, HMAC and AEAD primitives
