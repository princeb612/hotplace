## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# TLS advisor

## 1. Role


`sdk/net/tls/advisor` is the identifier and parameter lookup layer for TLS, DTLS and QUIC. It does not implement the cryptographic primitives themselves.

Its purpose is to translate protocol identifiers into metadata used by the implementation.

```text
TLS / DTLS / QUIC identifier
          │
          ▼
     tls_advisor
          │
   ┌──────┼────────┬──────────┐
   ▼      ▼        ▼          ▼
cipher  AEAD     extension   QUIC/TLS
suite   params   values     parameters
          │
          ▼
      sdk/crypto
```

## 2. Data Model

### Protocol metadata and lookup indexes

`tls_advisor` indexes static TLS/DTLS/QUIC resource records and exposes protocol-oriented lookup methods. The records cover cipher-suite IDs/names, version hints, alert/content/handshake parameters, extension types and values, AEAD parameters, QUIC packet/frame/transport-parameter identifiers, and configured cipher-suite/group lists.

A returned `tls_cipher_suite_t` describes the protocol suite and its mappings, including the associated crypto scheme and hash/MAC metadata. It is not an initialized cipher or digest implementation. The lower-level primitive vocabulary belongs to `sdk/crypto/advisor`, which maps crypto schemes, digest algorithms, curves, signature schemes and other primitive identifiers to `hint_*` metadata and, where applicable, separately resolves backend methods.

### The important data boundary

~~~text
TLS/DTLS/QUIC identifier
  -> tls_advisor resource record
       -> protocol meaning / version / suite mapping
       -> crypto scheme and digest identifiers
            -> crypto_advisor hint metadata
            -> optional backend method lookup
  -> handshake / protection / QUIC caller
~~~

TLS advisor maps protocol vocabulary; crypto advisor maps reusable cryptographic vocabulary and backend availability. Neither advisor owns handshake progression or performs the selected operation.

## 3. Behavior Model

### Initialization

`tls_advisor::get_instance()` checks the singleton's `_load` flag, takes the critical section and checks again before calling `load_resource()`. Resource loading builds the TLS parameter, extension/compression, QUIC, AEAD, version and miscellaneous indexes, then configures default cipher suites and TLS groups. The flag is set only after this loading path returns.

This is similar in shape to `crypto_advisor::get_instance()` and its guarded first-use initialization, but the build responsibilities differ: TLS advisor primarily indexes protocol records and defaults, while crypto advisor also probes the active OpenSSL version/provider for executable EVP cipher and digest methods and retains backend handles as needed.

### Lookup and follow-on use

1. A parser, handshake handler, protection calculation or QUIC component obtains a protocol identifier from wire data or local configuration.
2. The caller uses the corresponding TLS advisor lookup, such as `hintof_cipher_suite(code)`, a TLS-version classification/name method, an extension lookup, or a QUIC parameter/frame lookup.
3. The advisor searches the matching index and returns a record/name or a no-match result. This is metadata lookup; it does not update the session state.
4. If the result needs primitive metadata, the TLS suite record's scheme/hash mapping leads to `crypto_advisor`. The caller must distinguish a crypto hint from an available backend method and check both when the operation requires an executable provider.
5. Handshake/session logic decides whether the negotiated choice is valid in context. `tls_protection` performs transcript/key-schedule/protection work, while the QUIC layer applies QUIC packet framing and protection.

A successful TLS lookup means the identifier exists in the TLS resource tables; it does not prove backend availability, policy suitability, successful negotiation or end-to-end protocol support.

## 5. Relationships



- `sdk/net/tls/advisor/tls_advisor.cpp`
- `sdk/net/tls/advisor/resource.cpp`
- `sdk/net/tls/advisor/resource_ciphersuite.cpp`
- `sdk/net/tls/advisor/resource_aead_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_extensiontype_values.cpp`
- `sdk/net/tls/advisor/resource_quic.cpp`
- `sdk/crypto/advisor/`
- [TLS/DTLS/QUIC overview](README.md)
- [TLS advisor directory](advisor/README.md)
- [TLS protection/session model](tls-protection-and-session.md)
- [TLS key schedule](protection/tls_key_schedule.md)
### Relationship with crypto advisor

The two advisors map different identifier domains and should be read as a two-stage lookup, not as a chain where TLS advisor performs the cryptographic operation:

~~~text
TLS cipher-suite ID
  -> tls_advisor
       -> tls_cipher_suite_t
            ├─ TLS version / IANA and OpenSSL names
            ├─ crypto scheme
            └─ hash/MAC identifier
                  -> crypto_advisor
                       ├─ hint_cipher_t / hint_digest_t
                       └─ optional EVP backend method
  -> tls_protection or another caller checks and uses the result
~~~

The TLS advisor's suite record carries the protocol mapping. The crypto advisor resolves the mapped primitive identifiers into reusable crypto metadata, and may separately expose an executable backend method. Neither layer alone guarantees that the chosen suite is permitted by policy or successfully negotiated. The handshake/session caller owns those decisions, and `tls_protection` owns transcript/key-schedule/record-protection operations.

## 6. References

- [IANA TLS Parameters Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)
- [IANA QUIC Transport Parameters and Error Codes](https://www.iana.org/assignments/quic/quic.xhtml)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
