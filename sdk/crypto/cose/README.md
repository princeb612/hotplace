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

# CBOR Object Signing and Encryption (COSE)

## 1. Role

`sdk/crypto/cose` implements COSE message construction and processing on top of the CBOR object/encoding layer in `sdk/io/cbor`. CBOR supplies the data representation and serialization; COSE supplies the security semantics: protected and unprotected headers, algorithm identifiers, recipient/key-distribution layers, payload protection, signature/MAC structures, and the format-specific processing rules.

This is more than “crypto over CBOR.” COSE must construct the exact byte structures authenticated by each operation, attach the resulting ciphertext/tag/signature to the right message shape, and interpret recipient metadata during processing.

## 2. Data Model

### Message families and structures

| COSE family | Encoded message shape | Meaning |
|---|---|---|
| Encrypt / Encrypt0 | protected headers, unprotected headers, ciphertext, optional recipient tree | AEAD-protected payload. Encrypt has recipient information; Encrypt0 uses a directly supplied content key. |
| Sign / Sign1 | protected headers, unprotected headers, payload, signature (or signer collection for multi-signature form) | Digital signature over a COSE-defined Sig_structure, not over the raw CBOR serialization of the whole envelope. |
| Mac / Mac0 | protected headers, unprotected headers, payload, authentication tag (or recipient collection for Mac) | Keyed integrity/authentication over a COSE-defined MAC_structure. |
| Recipient layer | recipient headers, algorithm, key identifier and nested recipient data | Describes direct key use, key agreement, derivation or key wrapping used to obtain the content/MAC key. |
| COSE key | CBOR map of key type and key parameters | Maps CBOR key representation to hotplace key objects; it is not the primitive key implementation itself. |
| Countersignature | countersignature structures attached to a message/layer | Additional signature over the COSE-defined countersignature input. |

The in-memory tree is centered on `cose_composer`, a root `cose_layer`, protected/unprotected header objects, payload/ciphertext state, and zero or more `cose_recipient` layers. The composer maps this model to CBOR and parses encoded CBOR back into the model.

### CBOR's role

```text
CBOR values / maps / arrays / byte strings
                 ▲                 │
                 │ parse           │ encode
                 │                 ▼
       cose_composer ↔ cose_layer / cose_recipient
                              │
                       COSE message semantics
                  ┌───────────┼────────────┐
                  ▼           ▼            ▼
               Encrypt      Sign          MAC
                  │           │            │
            Enc_structure  Sig_structure  MAC_structure
                  └───────────┼────────────┘
                              ▼
                       sdk/crypto/basic
```

The CBOR layer does not decide what bytes belong in Enc_structure, Sig_structure, or MAC_structure. COSE constructs those inputs from the COSE context, protected-header serialization, external AAD and payload. The resulting ciphertext, tag or signature is then placed into the COSE message model and serialized as CBOR.

### Data consumed and produced between the model and primitive operations

| Data | In-memory representation / source | Role in the operation |
|---|---|---|
| Algorithm identifier (`alg`) | `cose_data` entry in a layer's protected or unprotected header; resolved through `crypto_advisor` | Selects operation family and algorithm metadata. Content encryption/MAC/signature algorithms belong to the body; key-distribution algorithms belong to recipient layers. |
| Protected-header bytes | `cose_protected`, serialized by `cbor()` | Exact serialized protected map is included in the COSE authenticated structure. Its values and encoding affect the operation input. |
| Unprotected headers | `cose_unprotected` / `cose_data` | Carry parameters such as `kid`, `iv`, `salt`, `epk` and other metadata. They are not interchangeable with protected-header bytes. |
| Payload / plaintext | `cose_binary` and `cose_param_plaintext` in layer/context parameters | Sender-side content supplied to the operation; the receiver-side payload is ciphertext for Encrypt/Encrypt0 and content for Sign/Sign1 or Mac/Mac0. |
| External AAD | `cose_param_external` in `cose_unsent` | Application-provided additional authenticated data. It is included in the Enc_structure, Sig_structure or MAC_structure but is not carried as the message payload; both parties must supply matching bytes. |
| `Enc_structure` | CBOR array serialized by `compose_enc_context()` | `[context, body_protected, external_aad]`; context distinguishes Encrypt/Encrypt0 and recipient-specific operations. Becomes AEAD associated data. |
| `Sig_structure` | CBOR array serialized by `compose_sign_context()` | `[context, body_protected, sign_protected?, external_aad, payload]`; context distinguishes Signature, Signature1 and CounterSignature. It is the signature input, not the final envelope bytes. |
| `MAC_structure` | CBOR array serialized by `compose_mac_context()` | `[context, protected, external_aad, payload]`; context distinguishes MAC and MAC0. The tag authenticates this serialized structure. |
| CEK / MAC key | `cose_param_cek` in layer parameters, possibly established through recipient processing | Key used by the content-encryption or MAC primitive. It is distinct from the recipient's key-agreement/wrapping key. |
| IV, Partial IV, salt | Header entries interpreted using algorithm metadata and layer scope | IV/nonce and KDF inputs. Presence, length and combination rules depend on the selected algorithm; these values are not interchangeable. |
| Recipient KDF context | Serialized COSE KDF Context: algorithm ID, PartyU/PartyV info, SuppPubInfo and optional SuppPrivInfo | Binds derived key material to the algorithm, parties, output length and protected-header context. Used during key distribution, not as body payload. |
| `kid` and COSE key parameters | Header metadata and `cbor_web_key` / `crypto_key` mapping | Identify/select key material and represent key parameters. A `kid` is a selector, not proof that a key is suitable for the algorithm. |
| Signature / tag / ciphertext | `cose_binary` single-item or payload state | Output of the primitive operation, placed into the appropriate COSE message slot. Where a backend returns ciphertext concatenated with a tag, COSE separates the fields using the algorithm's tag length. |

The model carries both *envelope data* and *operation-only parameters*. `cose_unsent` stages caller inputs such as external AAD and ephemeral IV/party information; these values are not all serialized as ordinary headers. `cose_data` stores typed map entries and binary payload material, while `cose_recipient` adds parent/child relationships and per-layer state.



## 3. Behavior Model

### The high-level API: specify intent, let COSE compose the envelope

The central API is `cbor_object_signing_encryption`. A caller opens a `cose_context_t`, configures the composer/layers, invokes `encrypt()`, `sign()` or `mac()`, and closes the context. For receive-side processing, a fresh context can parse the CBOR with `process()`, `decrypt()` or `verify()`.

The testcase demonstrates the intended ergonomics: select the operation algorithm in the protected header and call the operation. For example, the encryption path in `do_test_cose_encrypt()` sets the body algorithm and, when recipient key management is used, sets the recipient algorithm:

```cpp
cose_layer& body = handle->composer->get_layer();
body.get_protected().add(cose_key_t::alg, alg);

cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
recipient.get_protected().add(cose_key_t::alg, keyalg);

ret = cose.encrypt(handle, key, input, cbor);
```

The sign path sets the body's algorithm and calls `cose.sign(handle, key, input, cbor)`; the MAC path sets the body's MAC algorithm and, when key distribution is involved, a recipient algorithm before calling `cose.mac(...)`.

The important implementation point is that the caller does **not** manually construct every nonce, tag, cryptographic context, encoded structure, ciphertext field or signature field. The operation's preprocess path and composer fill/process the required message state using algorithm metadata, caller-provided keys/context and random generation where needed. This is not “algorithm name alone is enough for every use”: the caller must still provide appropriate key material, payload, any required recipient layer and any external AAD/context required by the application.

### Shared send-side pipeline

```text
open(&handle)
    └─ allocate cose_context_t + cose_composer
          │
caller configures headers, recipient tree, external AAD and key material
          │
encrypt / sign / mac
          ▼
preprocess
    ├─ validate algorithm categories for the requested operation
    ├─ initialize the body layer when an algorithm list is supplied
    ├─ store body alg and payload/plaintext
    ├─ create recipient layers for key-distribution algorithms
    └─ select key identifiers where required
          ▼
preprocess_random
    ├─ resolve each layer's algorithm hint/group flags
    ├─ fill missing kid where key selection is required
    ├─ generate algorithm-required IV and salt values
    └─ construct ephemeral/static EC public-key metadata where required
          ▼
process(send)
    ├─ walk nested recipient layers and process key distribution
    ├─ dispatch body operation by COSE tag/category
    └─ process countersignatures when present
          ▼
composer.compose → CBOR array → CBOR bytes → output
```

Overloads accepting an algorithm list build a skeleton from the requested categories. Overloads using a preconfigured composer retain the caller's model and run the random-preparation stage. `preprocess_random()` is metadata-driven; it does not mean every operation receives every possible random field.

### Encrypt flow

```text
protected body alg + optional recipient alg(s) + key + payload
                              │
                         encrypt(...)
                              ▼
                  preprocess / preprocess_random
                    ├─ inspect algorithm metadata
                    ├─ establish nonce/IV and other required fields
                    ├─ process recipient key distribution
                    └─ compose Enc_structure / external AAD
                              ▼
                  crypto/basic AEAD + KDF / key wrap
                              ▼
                  ciphertext + authentication tag
                              ▼
                       COSE CBOR serialization
```

For Encrypt, the body algorithm identifies content encryption; a recipient's algorithm describes how the content-encryption key is supplied, derived or wrapped. Those are separate roles. Encrypt0 has no recipient tree and uses the directly supplied key path. On receive, COSE parses the message, processes recipient layers and body in the appropriate order, reconstructs the same authenticated context, and delegates decryption/tag verification to the primitive layer.

#### Recipient key-distribution path

```text
recipient alg + recipient headers + selected recipient key
                         │
               process_keydistribution
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
   direct / direct+KDF            ECDH / RSA / AES-KW
          │                             │
          └──────────────┬──────────────┘
                         ▼
             establish or recover CEK
                         │
               store layer CEK parameter
                         ▼
           body AEAD or MAC operation
```

For ECDH-based derivation, COSE constructs a KDF context from the recipient algorithm, party information, requested key-data length, protected-header context and optional private context. Nested recipient children are processed before their containing recipient, then the body. The body algorithm protects the payload; the recipient algorithm determines how the required key is obtained.

### Sign flow

```text
protected body alg + key + payload
                 │
               sign(...)
                 ▼
      Sig_structure(context, protected, external_aad, payload)
                 ▼
         crypto/basic signature operation
                 ▼
              signature
                 ▼
           CBOR serialization
```

The protected header matters because its serialized form is part of the signed input. COSE signs the specified Sig_structure, not a byte-for-byte hash of the final CBOR envelope. Receive-side verification reconstructs that structure from the parsed message.

#### Signature input construction

`compose_sign_context()` chooses `Signature1` when there is no signer/recipient collection, `Signature` for the multi-signature form, and `CounterSignature` for a countersignature layer. It serializes the body's protected-header bytes, signer protected-header bytes when applicable, external AAD and payload into a CBOR array. `dosign()` then resolves the COSE algorithm to the primitive signature operation. Receive-side verification rebuilds this structure from parsed fields.

### MAC flow

MAC follows the same high-level composition pattern, but computes a keyed authenticator over the COSE MAC_structure. In the recipient form, key-distribution metadata is distinct from the body's MAC algorithm. The resulting tag is verified after the matching structure and key have been reconstructed.

#### Receive-side pipeline and result handling

```text
process(recv)
    ├─ composer.parse(CBOR bytes)
    │     └─ clear old model → parse CBOR array/tag → populate layers
    ├─ walk nested recipient layers (children before parent)
    ├─ process recipient key distribution
    ├─ dispatch Encrypt/Sign/MAC by algorithm category and message tag
    ├─ rebuild Enc_structure / Sig_structure / MAC_structure
    ├─ decrypt/authenticate, verify signature, or verify MAC
    ├─ process countersignature layers when present
    └─ combine operation status and expose body output
```

`verify()` delegates to `process()` and derives its boolean result from whether the overall return code is success. Per-layer return codes are collected, so mixed results are not silently treated as full success. Callers should distinguish successful CBOR parsing from successful authentication and check the return code and operation-specific output contract.

### Randomness and protected headers

The implementation contains `preprocess_random()` and algorithm/group metadata for fields such as IV/nonce, ephemeral key and key-agreement context. Those paths populate fields needed by the selected operation; the exact fields depend on the algorithm family. Protected headers are serialized as part of the cryptographic input, whereas unprotected headers carry metadata that is not covered by the same protected-header byte sequence. Security-sensitive algorithm selection and context must therefore be placed according to COSE's header rules, not merely whichever map is convenient.

#### IV and Partial IV: generation and receive-side processing

The `iv` and `partial_iv` header parameters participate in nonce construction, but the rule for generating a Partial IV must not be conflated with the receiver's processing of a received Partial IV. The RFC wording is conditional on the Partial IV generation procedure; it does not, by itself, establish that the receiver must repeat that generation operation verbatim.

In the receive-side `docrypt()` and `domac()` paths, hotplace combines the received Partial IV with the context IV using bitwise OR (`|=`). This is an intentional implementation choice, not evidence of a specification discrepancy merely because the operator differs from XOR. Describe and assess this code in the context of the RFC's generation-versus-processing distinction; do not label it non-conformant based on the operator alone. The Partial IV is an input to nonce construction, not the final nonce by itself.

### Algorithm inventory: what the source currently declares and tests

The advisor's resource table describes the following families. The testcase's self-generated loops exercise the listed algorithms/combination arrays, but a source entry or a test attempt is not a guarantee that every build/provider can execute every item.

| Operation family | Algorithms represented in source/test lists |
|---|---|
| Signatures | ECDSA ES256/ES384/ES512 and ES256K; EdDSA; RSA-PSS PS256/PS384/PS512; RSA PKCS#1 v1.5 RS256/RS384/RS512 and RS1; ML-DSA-44/65/87 in the OpenSSL 3.5+ guarded test path |
| MAC | HMAC HS256/64, HS256, HS384, HS512; AES-MAC-128/64, AES-MAC-256/64, AES-MAC-128/128, AES-MAC-256/128 |
| Content encryption | AES-GCM-128/192/256; AES-CCM variants represented by the COSE nonce/tag/key-size combinations in the testcase |
| Key distribution | direct; AES-KW-128/192/256; direct+HKDF-SHA-256/SHA-512; HKDF-AES-128/256; ECDH-ES and ECDH-SS with HKDF-SHA-256/SHA-512; ECDH-ES and ECDH-SS with AES-KW; RSA-OAEP variants |
| Hash metadata | SHA-1, SHA-256/64, SHA-256, SHA-512/256, SHA-384, SHA-512, SHAKE128 and SHAKE256 entries in the advisor resource table |

**Explicitly marked unsupported:** the COSE resource table attaches `cose_hint_not_supported` to the ChaCha20/Poly1305 encryption group. The algorithm has a metadata entry, but the group is marked unsupported and is not in the testcase's content-encryption array. The current source does not establish a reason for that exclusion, so this document does not attribute it to a particular security rationale.

For other algorithms, use three separate evidence levels: (1) metadata exists in `resource_cose.cpp`; (2) an operation is listed in `testcase_cose.cpp`; (3) that operation actually runs successfully in a specific build/provider. This documentation pass did not rerun the suite, so it does not claim a fresh runtime support matrix.

### CWT boundary

CWT (CBOR Web Token) uses CBOR claims and commonly uses COSE as its protection envelope, but CWT claim semantics are not the same thing as COSE message processing. The COSE code can protect a CBOR payload; the source reviewed here does not expose a separate CWT claims-validation API for registered claims, issuer/audience policy or application authorization. Those checks belong to the CWT/application layer above the COSE envelope.

## 5. Relationships

- `sdk/io/cbor/` — CBOR values, maps, arrays, byte strings, parsing and serialization.
- `sdk/crypto/basic/` — AEAD, signatures, MAC, keys, key exchange and KDF operations.
- `sdk/crypto/advisor/` — COSE algorithm/group metadata and mappings to primitive/key details.
- `sdk/crypto/jose/` — related JSON-oriented security-object layer; it has analogous signing/encryption responsibilities but distinct identifiers and serialization.
- `test/testcase/cose/testcase_cose.cpp` — the `do_test_cose_encrypt`, `do_test_cose_sign`, `do_test_cose_mac` examples and algorithm-family arrays.

### Source-test example: why the “it's fun” test matters

`test_cose()` begins with the label `it's fun`. It generates/assembles test keys, iterates the declared signature algorithms, content-encryption algorithms and key-management algorithms, then runs sign/encrypt/MAC and receive-side verification/decryption through fresh contexts. This is a particularly useful example of hotplace's design: the test specifies the intended algorithm(s), while COSE builds the protocol-shaped protected input and message envelope around the primitive operations.

The tests assert operation return status and exercise receive-side processing. The shown snippets do not always assert that the decrypted plaintext equals the original input or inspect the boolean verification result, so do not interpret the test alone as proving every semantic property of each combination.

### Implementation entry points

- `cbor_object_signing_encryption.hpp/.cpp` — lifecycle, orchestration and processing.
- `cbor_object_signing_encryption_crypt.cpp`, `_sign.cpp`, `_mac.cpp` — operation-specific flows and COSE authenticated structures.
- `cose_composer.hpp/.cpp`, `cose_data.hpp`, `cose_protected.hpp/.cpp`, `cose_unprotected.hpp/.cpp` — in-memory message and CBOR composition.
- `cose_recipient.hpp/.cpp`, `cose_recipients.hpp/.cpp` — recipient/key-distribution tree.
- `cbor_web_key.hpp/.cpp` — COSE key representation.
- `sdk/crypto/advisor/resource_cose.cpp` — algorithm/group metadata and explicit support flags.

## 6. References

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949).
- [RFC 9052 — CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052).
- [RFC 9053 — CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://www.rfc-editor.org/rfc/rfc9053).
- [RFC 8610 — Concise Data Definition Language (CDDL)](https://www.rfc-editor.org/rfc/rfc8610) — notation for CBOR and JSON data structures.
- [RFC 8392 — CBOR Web Token (CWT)](https://www.rfc-editor.org/rfc/rfc8392).
- [RFC 9338 — COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338).
- [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml) — algorithm, header, key-type and curve identifiers.
