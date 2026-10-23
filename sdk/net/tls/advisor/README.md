## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS/QUIC algorithm and parameter advisor

## 1. Role

`tls_advisor` is a lookup/resource provider for TLS, DTLS and QUIC identifiers and their implementation metadata. It exposes hint structures to callers so handshake, record protection and packet code can resolve a negotiated identifier into parameters; it does not itself execute cryptographic algorithms or advance handshake state.

## 2. Data Model

### Resource records and runtime indexes

The TLS advisor follows the same broad design principle as `sdk/crypto/advisor`: static resource records are indexed into lookup maps, and callers receive metadata pointers or names rather than an executable cryptographic operation. Its domain is protocol vocabulary—TLS/DTLS versions and parameters, cipher suites, extension types/values, AEAD identifiers, QUIC packet/frame/transport-parameter identifiers, alert names, and related enums.

The main resource families are populated from `resource.cpp`, `resource_ciphersuite.cpp`, `resource_aead_parameters.cpp`, `resource_tls_parameters.cpp`, `resource_tls_extensiontype_values.cpp`, and `resource_quic.cpp`.

| Index family | Key | Result / purpose |
|---|---|---|
| Cipher-suite codes and names | IANA/OpenSSL name or 16-bit suite code | `tls_cipher_suite_t` record and suite metadata |
| TLS parameter maps | Numeric enum/code | Alert, record content type, handshake type, KDF ID, PSK mode and other names |
| Extension/compression maps | Extension or compression code/name | Protocol-field interpretation |
| AEAD map | AEAD identifier | TLS AEAD parameter record |
| QUIC maps | Parameter, frame, error or packet-type identifier | QUIC diagnostic/interpretation names |
| Version hints | TLS/DTLS version enum | Version classification and version name |
| Cross-advisor mappings | Cipher suite → crypto scheme/digest metadata | Follow-up lookup through `crypto_advisor` |

The TLS advisor's records are not the same kind of objects as the crypto advisor's `hint_cipher_t`, `hint_digest_t`, or backend `EVP_CIPHER`/`EVP_MD` handles. TLS metadata tells callers how a protocol identifier maps; `crypto_advisor` describes reusable primitives and may separately resolve a backend method. A TLS cipher-suite entry can therefore be present without proving that a provider can execute every operation associated with it.

### Intermediate data and ownership

The resource records are static metadata. The advisor's maps hold pointers to those records and are owned by the shared singleton; callers use the returned pointers as lookup results, not as objects to delete. The singleton also retains configuration such as the configured/default cipher-suite and TLS-group lists used by its selection helpers. This is different from `crypto_advisor`, whose initialization additionally probes OpenSSL methods and retains backend method handles on OpenSSL 3+.

## 3. Behavior Model

### Initialize the shared advisor

~~~text
tls_advisor::get_instance()
  -> check _load
  -> lock + recheck _load
  -> load_resource()
       ├─ load TLS parameter tables
       ├─ load extension/compression tables
       ├─ load QUIC tables
       ├─ load AEAD parameter tables
       ├─ load TLS/DTLS version hints and other resources
       ├─ configure default cipher suites
       └─ configure default TLS groups
  -> _load = true
  -> return shared singleton
~~~

The double check prevents concurrent first-use calls from populating the maps at the same time. Unlike `crypto_advisor::build()`, TLS advisor initialization primarily indexes protocol metadata and establishes defaults; it does not itself fetch the full set of OpenSSL cipher/digest implementations.

### Resolve a protocol identifier

1. A parser, handshake path, protection setup, or QUIC component obtains an identifier from the wire representation or local configuration.
2. It calls the matching `tls_advisor` lookup, such as `hintof_cipher_suite(code)`, a version/name conversion, an extension lookup, or a QUIC parameter/frame name lookup.
3. The advisor searches the corresponding map and returns a pointer/name or a no-match result. Lookup does not mutate handshake state.
4. When a cipher-suite lookup must be connected to a primitive, the TLS advisor follows the suite record's crypto scheme/digest mapping into `crypto_advisor`. That second lookup provides primitive metadata; an executable backend handle, where needed, must still be resolved and checked separately.
5. The caller uses the metadata to interpret a field, make a negotiation decision, or configure protection. The advisor does not select the handshake stage, update the transcript, derive traffic keys, or perform encryption.

### The two-advisor path

~~~text
wire/configuration cipher-suite ID
  -> tls_advisor
  -> tls_cipher_suite_t
       ├─ protocol properties / version classification
       ├─ crypto scheme
       └─ hash/MAC mapping
             -> crypto_advisor
                  ├─ hint_cipher_t / hint_digest_t
                  └─ optional EVP method lookup
  -> caller validates availability and policy
  -> tls_protection / crypto operation
~~~

A successful TLS metadata lookup means that the identifier is recognized by the resource tables. It does not prove backend availability, policy suitability, successful negotiation, or end-to-end support. Likewise, a successful crypto metadata lookup is not itself an encryption/signature operation.

## 4. Relationships
- `tls_advisor.cpp`, `tls_advisor_aead_parameters.cpp`, `tls_advisor_quic.cpp`.
- `tls_advisor_tls_extensiontype_values.cpp`, `tls_advisor_tls_parameters.cpp`.
- `resource.cpp`, `resource_aead_parameters.cpp`, `resource_ciphersuite.cpp`, `resource_quic.cpp`, `resource_tls_extensiontype_values.cpp`, `resource_tls_parameters.cpp`.
- `sdk/crypto/advisor/` — primitive, key, curve, signature and algorithm metadata.
- [TLS protection](../protection/README.md) — consumes negotiated parameters for key schedule and protection.
- [TLS session support](../session/README.md) — handshake/session state.
- [QUIC](../quic/README.md) — QUIC packet/frame and session integration.
- [TLS overview](../README.md).

## 5. References
No external references are currently listed.
