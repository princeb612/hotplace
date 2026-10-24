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

# Key material: representation, construction, selection, and exchange

## 1. Role

`sdk/crypto/basic/key/` is hotplace's common key-material layer. It sits beneath protocol-facing code and provides a shared way to represent, construct, select, import/export, generate, inspect, and use cryptographic keys. This makes it central to two different kinds of consumer:

- **JOSE and COSE** work with portable security-object formats such as JWK and COSE_Key. Those formats carry key parameters and metadata; hotplace converts them into and out of its common key representation so signing, verification, encryption, and key-agreement operations can use the material.
- **TLS key exchange** works with negotiated groups and handshake key shares. It needs local key-pair generation, public-share extraction, peer-share processing, and shared-secret derivation. The key layer supplies these operations, while TLS remains responsible for the handshake and its protocol state.

The shared representation is OpenSSL's `EVP_PKEY`, wrapped by `crypto_key_object` and held in a `crypto_key` collection. Supporting classes provide format dispatch, family-specific construction, generation, parameter extraction, and group-based exchange.

Keep four concepts separate:

1. **Key object** — the local cryptographic object, potentially including private material.
2. **Serialized key representation** — for example JWK, COSE_Key, PEM, or DER; each format has its own fields and encoding rules.
3. **Public key share** — protocol data sent to a peer for a key-agreement operation.
4. **Shared secret** — output derived by a key-agreement or KEM operation, not a serialized private key or a public share.

The directory supplies common key operations, not the complete JOSE, COSE, or TLS protocol. Those modules decide when and why a key is used and how the resulting operation fits into a message or handshake.

## 2. Data Model
### 2.1 `keydesc`: metadata associated with a key

`keydesc` carries four values:

| Field | Meaning |
|---|---|
| `kid` | String identifier used as the key-map key and for key lookup. |
| `alg` | Algorithm label associated with the key. It is metadata; the underlying OpenSSL type is determined from `EVP_PKEY`. |
| `use` | Usage flags used during selection, such as general use, encryption, or signature use. Constructors default to `use_any` unless a usage is supplied. |
| `group` | Numeric group identifier available to callers associating a key with a group; defaults to zero. |

These values are not interchangeable. `kid` identifies an entry; `alg` describes an intended algorithm; `use` restricts how a key may be selected; and `group` can associate material with a protocol group. The `set_use_enc()` and `set_use_sig()` setters apply bit masks to the current flags, so their behavior should be read as flag manipulation rather than assumed to be ordinary enum assignment.

### 2.2 `crypto_key_object`: one OpenSSL key plus its description

A `crypto_key_object` stores:

- `_pkey`: an `EVP_PKEY*` for the key material;
- `_x509`: an optional `X509*` certificate associated with the key;
- `_desc`: the `keydesc` metadata.

Constructors receiving existing OpenSSL objects call `EVP_PKEY_up_ref()` and, when applicable, `X509_up_ref()`. The wrapper therefore acquires its own reference instead of implicitly taking over the caller's reference. Copy and move operations have distinct ownership behavior; callers must follow the actual path rather than infer ownership transfer from a constructor call.

The accessors return `const EVP_PKEY*` and `const X509*`, but `const` does not extend lifetime. With `up_ref = false`, a pointer returned by the collection is borrowed and depends on the owner remaining alive. With `up_ref = true`, the caller receives an additional OpenSSL reference and must eventually release it.

**Maintainer note:** in the inspected source, `crypto_key_object::release()` calls `EVP_PKEY_free()` / `X509_free()` without resetting the stored pointers. The destructor calls `release()`, and `crypto_key::clear()` explicitly releases mapped objects before clearing the map. Copy assignment also releases before copying. This warrants a focused ownership/lifetime audit, including repeated release and self-assignment; it is a source-level observation, not a claim that a runtime failure has been reproduced.

### 2.3 `crypto_key`: collection and selection boundary

`crypto_key` stores `crypto_key_object` values in `_key_map`, keyed by `kid`. Its API covers collection operations such as `add()`, `append()`, `erase()`, `clear()`, `size()`, and `for_each()`, plus selection and access by key identifier, key type, NID, algorithm, usage, or TLS group.

`add()` checks that a key object has a non-null public-key object, that its usage is not `use_unknown`, and that the underlying key type can be recognized. It then inserts using `kid` as the map key. The insertion result from `emplace()` is not checked, so a successful return from `add()` does not prove a new entry was inserted if that identifier already exists. Do not treat its return code as a duplicate-`kid` detector.

Selection overloads connect protocol-facing identifiers to the stored key material. They include JOSE encryption identifiers (`jwa_t`), JOSE signature identifiers (`jws_t`), COSE algorithm identifiers (`cose_alg_t`), generic signature identifiers, and TLS groups. The algorithm overloads use `crypto_advisor` to map a protocol vocabulary to internal metadata and test the candidate key. Selection also considers usage flags and, for some overloads, key type. Callers should select using the protocol's actual requirements instead of relying on the first key in the collection.

The `up_ref` parameter is an explicit ownership choice. It does not mean the collection itself becomes thread-safe for arbitrary pointer use after the lookup guard ends, nor does a critical-section guard keep a borrowed pointer alive after the owning object or collection is destroyed.

### 2.4 `crypto_keychain`: format loading and family-specific construction

`crypto_keychain` is the common interface for importing, exporting, encoding, decoding, and constructing keys. Its `keyflag_t` modes distinguish:

- `key_ownspec`: hotplace/application-defined key input, including JWK- or COSE-oriented parameter input;
- `key_pemfile`: PEM-encoded input;
- `key_certfile`: certificate input;
- `key_derfile`: DER-encoded input.

The mode determines how input is loaded; it does not name a cryptographic algorithm. Family-specific `add_*` functions construct RSA, DH, DSA, EC, OKP, and octet keys from their corresponding parameters. OpenSSL 3-specific entry points cover named algorithms and encoder/decoder operations.

The parameter sets differ by family. RSA uses integer components such as `n`, `e`, and optional private/CRT values; DH and DSA use public/private and domain parameters; EC uses curve identity and public/private components; OKP uses raw key material; and octet keys hold symmetric key bytes. Decoding text into bytes and constructing a valid algorithm key are separate operations.

The PEM loader scans for public keys and private keys rather than promising exactly one key per input. The certificate loader parses X.509, extracts its public key, and can retain the certificate alongside that key. The DER path attempts private-key decoding and then certificate decoding with public-key extraction; it is not a general parser for every ASN.1 object. File helpers route mapped file contents through the same buffer-based load path.

### 2.5 `crypto_keygen`: readable parameters instead of enum-heavy setup

`crypto_keygen` is a convenience layer over the family-specific key builders. Callers identify the algorithm by name (for example, `"P-256"`, `"X25519"`, `"rsaEncryption"`, or `"ffdhe2048"`) and provide key components using familiar parameter names. They do not need to memorize the internal `crypt_item_t` values.

The constructor binds a destination `crypto_key*`, an algorithm identity and a text-encoding choice. The parameter collection can represent encoded text, already-decoded bytes, or boolean metadata such as EC `ybit`. The default text encoding is base16; base16 RFC form, base64 and base64url are also available through `encoding_t`.

The algorithm may be supplied as a readable name or an internal `crypt_item_t`. Names such as `"P-256"`, `"X25519"`, `"rsaEncryption"` and `"ffdhe2048"` identify different key families or named groups; parameter names are interpreted within that selected family rather than as a universal key schema.

#### Parameter quick reference

Parameter names are interpreted in the context of the selected algorithm. A name that is meaningful for one family is not automatically valid for another.

| Algorithm family / representation | Key-component parameters | Meaning |
|---|---|---|
| RSA (`rsaEncryption`) | `n`, `e`, optional `d` | Modulus, public exponent, and private exponent. Public-only construction needs `n` and `e`; `d` adds private material. |
| RSA-PSS (`RSASSA-PSS`) | `n`, `e`, optional `d` | RSA-PSS key representation. The generic builder dispatches through the RSA parameter set, but RSA-PSS construction uses a distinct OpenSSL 3 path. |
| EC (`P-256`, `P-384`, `P-521`, etc.) | `x` + `y`, optional `d`; or `x` + boolean `ybit`, optional `d`; or `uncompressed`, optional `d` | Affine public coordinates; compressed-point form represented by X plus Y parity/sign; or the encoded uncompressed public point. The curve comes from the algorithm name. |
| OKP (`X25519`, `X448`, `Ed25519`, `Ed448`) | `x`, optional `d` | Raw public key bytes and optional private key bytes. OKP does not use an EC `y` coordinate. |
| DH | `y` + optional `x`; or domain parameters `p`, `q`, `g` plus optional `x` | Public value `y`, private value `x`, and finite-field domain parameters when constructing the group/key from explicit parameters. The algorithm name may identify a named group such as FFDHE. |
| DSA | `y`, optional `x`, and `p`, `q`, `g` | Public/private values and DSA domain parameters. |
| Symmetric octet key | `k` | Raw symmetric key bytes. This case is available through the builder's internal dispatch when the selected name resolves to the octet key type. |
| ML-KEM, ML-DSA, SLH-DSA | Family-specific key material; no shared coordinate/component tuple | These algorithms use algorithm-specific named-key or encoding representations rather than the generic RSA/EC/DH parameter sets. The supported construction route is described in the Behavior Model. |

The accepted names describe data supplied to each family builder, not an automatic inference mechanism. The branch priority for EC point representations and the distinct DH construction routes are described in the Behavior Model.

#### Encoding inputs

- The default text encoding is base16. The constructor also accepts base16 RFC form, base64, or base64url through `encoding_t`.
- `set(name, const char*)` stores text for decoding during `build()`; `set(name, binary_t&&)` supplies bytes directly; `set(name, bool)` is used for boolean metadata such as `ybit`.

### 2.6 Algorithm families and construction paths

The family-specific functions are not just aliases around one generic constructor. Each family has a different parameter model and public representation.

| Family | Key representation | Construction path and important distinction |
|---|---|---|
| RSA / RSA-PSS | Modulus `n`, exponent `e`, optional private exponent `d` and CRT components | `add_rsa()`; generation and construction from supplied parameters are separate routes |
| EC (short-Weierstrass curves) | Curve/NID, public coordinates `x,y`, optional private scalar `d` | `add_ec()`; compressed and uncompressed point encodings have dedicated entry points |
| OKP (e.g. X25519, Ed25519) | Raw public bytes `x`, optional private bytes `d`; no separate `y` coordinate | `add_okp()`; `add_ec2()` is a convenience dispatcher for EC and OKP, not a synonym for EC |
| DH | Public value `y`, private value `x`, and, where required, domain parameters `p,q,g` | `add_dh()` |
| DSA | Public/private values and domain parameters | `add_dsa()` |
| FFDHE | Finite-field DH using a named group such as `ffdhe2048` | Group/NID metadata resolves the named parameters; this is DH-style key material, not an EC curve |
| ML-KEM | KEM key material plus a separate encapsulation ciphertext (capsule) | OpenSSL 3.5 named-algorithm paths and the PQC encapsulation/decapsulation interface |
| ML-DSA / SLH-DSA | OpenSSL 3 named post-quantum signature algorithms | Generic OpenSSL 3 by-name generation/encoding paths; not every generic parameter builder supports them |

The last row needs an important qualification. The key-type enums and OpenSSL 3 by-name entry points exist, and `crypto_keygen::build()` recognizes the `kty_mldsa`, `kty_mlkem`, and `kty_slhdsa` cases syntactically. However, those cases are currently empty in that dispatch function. Therefore the ordinary `set(...).build()` parameter route must not be described as constructing ML-DSA, ML-KEM, or SLH-DSA keys. The separate OpenSSL 3 path uses provider/name-based operations such as `EVP_PKEY_CTX_new_from_name()`, `EVP_PKEY_keygen()`, and `EVP_PKEY_fromdata()`; actual availability depends on the OpenSSL version and loaded provider. The advisor's version table marks ML-KEM and the listed hybrid group names as requiring OpenSSL 3.5, but a version gate alone does not establish support for every hotplace API or operation.

### 2.7 EC point input: compressed versus uncompressed

Compressed and uncompressed are public-point representations, not different EC algorithms.

| Entry point | Input | Interpretation |
|---|---|---|
| `add_ec()` | Separate `x`, `y`, optional `d` | Construct from coordinate components |
| `add_ec_compressed()` | X coordinate, `ysign` bit, optional private scalar `d` | Reconstruct/select the EC point from X and the Y parity/sign information |
| `add_ec_uncompressed()` | Encoded public-point bytes, optional private-key bytes | Interpret the supplied point in uncompressed form for the selected curve |
| `add_okp()` | Raw `x`, optional `d` | Build an OKP key; there is no separate EC `y` coordinate to reconstruct |
| `add_ec2()` | Generic `x,y,d` interface | Resolve the named algorithm and dispatch to EC or OKP |

The distinction matters at protocol boundaries. In the TLS key-share path, group metadata determines the algorithm and the expected representation. The hybrid key-exchange implementation explicitly uses uncompressed EC point encoding when an EC component is part of the combined share/capsule buffer.

### 2.8 `crypto_keyexchange`: group and local-key state

A `crypto_keyexchange` instance stores a `tls_group_t` and a local `crypto_key` collection. Group metadata obtained through `crypto_advisor` describes the algorithm family or families, support flags, component key types, public-share sizes and—where a KEM is involved—capsule sizes.

The model distinguishes locally retained key material from public share bytes, KEM capsule bytes and the derived shared secret. These values have different roles and are not interchangeable: a share or capsule crosses the endpoint boundary, while the private key remains local and the shared secret is consumed by the protocol's subsequent key schedule. Hybrid groups add an ordered component layout; the exact order and lengths are part of the selected group's metadata.

## 3. Behavior Model

### 3.1 Key construction: named input to family-specific object

```text
algorithm name ──> crypto_advisor (key type + NID)
                         |
              +----------+-----------+
              |                      |
            gen()                  build()
              |                      |
      keychain generation     collect named parameters
                                     |
                           decode text to bytes
                                     |
                            dispatch by key type
                                     |
                     RSA / EC / OKP / DH / DSA / octet
                                     |
                             crypto_key collection
```

The two routes express different intents. `gen()` asks the keychain to generate fresh material for the resolved algorithm; it does not build from the parameter values collected by `set()`. `build()` decodes the supplied values and dispatches to the selected key-family constructor. After `build()` dispatches, its internal parameter maps are cleared, so the builder should be treated as a one-shot parameter collection for that build. The chained return value is the builder itself, not a success status.

The API distinction is visible in these representative call shapes:

```cpp
crypto_key key;

// Generate a fresh EC key pair.
crypto_keygen(&key, "P-256")
    .set(keydesc("p256-generated"))
    .gen();

// Build an X25519 key from encoded public/private components.
crypto_keygen(&key, "X25519")
    .set(keydesc("x25519-imported"))
    .set("x", "...")
    .set("d", "...")
    .build();

// Build an EC key from an uncompressed point representation.
crypto_keygen(&key, "P-256")
    .set(keydesc("p256-point"))
    .set("uncompressed", "04...")
    .build();
```

The string-parameter overload resolves each name through `crypto_advisor::itemof()` and stores the resulting `crypt_item_t` entry. String values are decoded using the configured encoding; binary overloads pass bytes directly; `ybit` is boolean metadata rather than encoded bytes. The generic `.set(...).build()` dispatch currently has empty cases for ML-KEM, ML-DSA and SLH-DSA; use the separate OpenSSL 3 named-algorithm/key-encoding paths where supported rather than assuming those families can be imported through the generic parameter map.

#### EC and DH dispatch are data-dependent

For EC input, the builder chooses one representation in a fixed order:

1. If both `x` and `y` are present, use the affine-coordinate path.
2. If `x` is present but `y` is absent, look for boolean `ybit` and use the compressed-point path.
3. If `x` is absent, look for `uncompressed` and use the uncompressed-point path.

It does not infer missing coordinates from an incomplete set of parameters. The curve identity comes from the selected algorithm name; the point representation comes from the supplied parameter combination.

For DH, the dispatcher first checks whether `y` is present. If so, it sends `y` and optional `x` to the public/private-value construction path. Otherwise, it sends `p`, `q`, `g` and optional `x` to the explicit-domain-parameter path. DSA uses its family constructor with the available public/private and domain values. Family constructors and OpenSSL remain responsible for validating whether the resulting key material is valid.

### 3.2 Key selection is where protocol vocabulary meets key material

JWK and COSE_Key carry standard key parameters and format-specific metadata. The key layer is responsible for turning supported representations into common key objects and making those objects available to operations. The protocol layer still determines which algorithm is negotiated or declared and what constraints apply.

The selection overloads make this boundary visible:

- JOSE encryption algorithms are resolved through `hintof_jose_algorithm()`;
- JOSE signature algorithms are resolved through `hintof_jose_signature()`;
- COSE algorithm identifiers are resolved through `hintof_cose_algorithm()`;
- TLS group selection uses group metadata rather than a JWK/COSE algorithm label.

A `kid` is a lookup identity, not proof that the key is suitable. Algorithm, key type, usage, group, and available key components must still match the operation. A selection result also does not by itself prove that an encoded key is valid for every use allowed by the surrounding protocol.

### 3.3 Loading and construction are not protocol validation

The load path determines how bytes are decoded and which object type is attempted. The construction path determines whether the supplied components can form a supported OpenSSL key. Neither path alone implements all protocol-level validation, authorization, trust decisions, or algorithm-policy checks.

This matters especially for keys with both public and private components. A public-only JWK or COSE_Key can be appropriate for verification or peer key agreement, while a private key may be required for signing or decapsulation. The key container does not make private material public merely because it can export a public representation; callers must request the intended representation and operation.

### 3.4 Classical key agreement: share bytes are not key objects

The group-specific key-generation path obtains group metadata, checks support flags, and creates the appropriate local component keys. `keyshare()` extracts public components into the output buffer. For hybrid groups it extracts the additional component and appends it according to that group's layout.

When the peer share arrives, `exchange()` dispatches according to the selected group and combines the peer's encoded public material with local private material. The group metadata determines how the incoming bytes are split and which algorithm implementation handles each component. The resulting shared secret is operation output; it is not the original public share and must be passed into the protocol's subsequent key schedule by the appropriate consumer.

The concrete flow in `test/testcase/crypto/key/testcase_keyexchange.cpp` uses two independent local stores and exchange objects:

```text
Alice: keygen(local store) -> public share A
Bob:   keygen(local store) -> public share B

Bob derives using share A  -> secret B
Alice derives using share B -> secret A

compare(secret A, secret B)
```

The testcase checks the generated share lengths against the selected group's metadata and compares the two derived secret byte strings. Key dumps are diagnostic output; the shared-secret equality is the central agreement assertion. This is a group-level key-agreement example, not a complete TLS handshake or key-schedule test.

### 3.5 TLS owns handshake orchestration

TLS uses `crypto_keyexchange` for key-share operations, but the key layer does not own the TLS handshake. TLS chooses and negotiates supported groups, places key shares in handshake extensions, retains the relevant state, processes peer messages, and feeds the shared secret into the TLS key schedule. The key layer supplies the cryptographic material and group-level operation.

This distinction is particularly important in TLS 1.3: the public key share is handshake data, while traffic secrets and record-protection keys are derived later through the TLS key schedule. The key directory should not be described as if `crypto_keyexchange` alone implements the TLS handshake or the full key schedule.

### 3.6 Hybrid groups: how the three combinations are distinguished

The implementation does not parse a group name to guess its components. It asks `crypto_advisor::hintof_tls_group()` for a `hint_group_t`. The hint contains a `first` component and, for hybrid groups, a `second` component. Each component specifies its key type (`kty`), algorithm NID, public-key size (`keysize`), and—when it is ML-KEM—capsule size (`capsulesize`). The `tls_flag_hybrid` flag selects the two-component path; the component types decide which algorithm is called and where each byte range belongs.

The current definitions in `sdk/crypto/advisor/resource_tls.cpp` are:

| Group | First component | Second component | Combined buffer consumed by `decaps()` |
|---|---|---|---|
| `secp256r1mlkem768` | EC P-256, uncompressed point: 65 bytes | ML-KEM-768, public key: 1184 bytes; capsule: 1088 bytes | EC point (65) || ML-KEM capsule (1088) |
| `x25519mlkem768` | ML-KEM-768, public key: 1184 bytes; capsule: 1088 bytes | X25519, public share: 32 bytes | ML-KEM capsule (1088) || X25519 share (32) |
| `secp384r1mlkem1024` | EC P-384, uncompressed point: 97 bytes | ML-KEM-1024, public key: 1568 bytes; capsule: 1568 bytes | EC point (97) || ML-KEM capsule (1568) |

These are the sizes recorded in the current group metadata and used by this implementation. They are not universal sizes for all EC curves or KEM algorithms.

The encapsulation path branches on `first.kty` and `second.kty`:

- For `secp256r1mlkem768` and `secp384r1mlkem1024`, the components are EC then ML-KEM. The EC contribution is encoded as an uncompressed point and placed before the ML-KEM capsule.
- For `x25519mlkem768`, the order is ML-KEM then OKP/X25519. The ML-KEM capsule is produced first; the X25519 public share is appended after it.

The decapsulation path mirrors these layouts. It validates the total input size from the metadata, processes the first component according to `first.kty`, then reads the second component from the corresponding offset. It performs ML-KEM decapsulation and the classical DH agreement for the EC/X25519 component. That is why the implementation computes offsets conditionally on whether the first component is ML-KEM. Assuming that every hybrid group is “EC first, KEM second” would parse `x25519mlkem768` incorrectly.

```text
secp256r1mlkem768
  EC P-256 share (65) | ML-KEM-768 capsule (1088)
  first = EC           second = ML-KEM

x25519mlkem768
  ML-KEM-768 capsule (1088) | X25519 share (32)
  first = ML-KEM       second = OKP

secp384r1mlkem1024
  EC P-384 share (97) | ML-KEM-1024 capsule (1568)
  first = EC           second = ML-KEM
```

The component order is therefore an explicit property of the group metadata and its implementation, not a convention that can safely be inferred from the group name alone. Keep the metadata, byte offsets, share generation, encapsulation, and decapsulation paths synchronized when adding or changing groups.

### 3.7 Key-exchange lifecycle

The group metadata selects both the operation family and the layout used to interpret the bytes:

```text
tls_group_t
    |
    v
crypto_advisor::hintof_tls_group()
    |
    v
component metadata (key type, NID, sizes, hybrid flag)
    |
    +-- keygen() ──> local key material
    |                    |
    |                    v
    |               keyshare() ──> public share bytes
    |
    +-- classical exchange()
    |        local private key + peer share
    |                    |
    |                    v
    |              shared secret
    |
    +-- KEM encaps()
    |        peer public key ──> capsule + shared secret
    |
    +-- KEM decaps()
             local private key + capsule
                         |
                         v
                   shared secret
```

For a classical group, `keygen()` creates local key material and `keyshare()` extracts the public component. The convenience `keygen(key, kid, share)` combines those two steps. `exchange()` consumes the peer's encoded share together with local private material. If matching material already exists for the requested identifier and component, the implementation can return `already_exist` instead of generating another key.

KEM encapsulation is a different exchange shape: the peer's public key produces a capsule and shared secret; the private-key holder uses its private key and that capsule in `decaps()` to derive the corresponding secret. A hybrid group composes multiple component operations, and the group metadata determines each component's byte offset and ordering. The caller passes the resulting shared secret to the protocol's key schedule; this class does not implement the TLS handshake or schedule itself.

### 3.8 Failure handling and sensitive data

The implementation returns status codes for invalid parameters, unsupported algorithms or groups, failed decoding/construction, and OpenSSL operation failures. A non-null output buffer or populated collection is not proof of success; callers must check the result of each operation.

OpenSSL reference counting controls object lifetime; it does not erase application copies of private values or derived secrets. Callers remain responsible for the lifetime and handling of sensitive byte buffers. Borrowed pointers must not outlive the object or collection that owns their reference, and callers that request `up_ref = true` must release the extra reference.

### Practical use: exchange public shares and compare derived secrets

The key-exchange testcase creates independent key stores for two peers. Each side generates a local key pair and a public share, then consumes the other peer's share to derive a secret:

```cpp
return_t exchange_two_peers(tls_group_t group) {
    crypto_key keystore_alice;
    crypto_keyexchange keyexch_alice(group);
    binary_t share_alice;
    binary_t secret_alice;

    return_t ret = keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
    if (errorcode_t::success != ret) {
        return ret;
    }

    crypto_key keystore_bob;
    crypto_keyexchange keyexch_bob(group);
    binary_t share_bob;
    binary_t secret_bob;

    ret = keyexch_bob.keygen(&keystore_bob, "bob", share_bob);
    if (errorcode_t::success != ret) {
        return ret;
    }

    ret = keyexch_bob.exchange(&keystore_bob, "bob", share_alice, secret_bob);
    if (errorcode_t::success != ret) {
        return ret;
    }

    ret = keyexch_alice.exchange(&keystore_alice, "alice", share_bob, secret_alice);
    if (errorcode_t::success != ret) {
        return ret;
    }

    return (secret_alice == secret_bob) ? errorcode_t::success : errorcode_t::mismatch;
}
```

The function parameter makes the negotiated/tested group explicit; each peer gets an independent key store, and every operation status is checked before the derived secrets are compared. The example separates three values that are easy to conflate: each peer's local key object, the public share exchanged over the protocol, and the locally derived shared secret. The testcase compares both secrets; a real protocol must also authenticate the peer and bind the exchange to its handshake transcript. A matching secret alone does not authenticate the peer or establish a secure channel.

Source: [testcase_keyexchange.cpp](../../../../test/testcase/crypto/key/testcase_keyexchange.cpp).

## 5. Relationships
### 4.1 Internal implementation boundaries

- `sdk/crypto/basic/crypto_key.hpp` declares `keydesc`, `crypto_key_object`, and `crypto_key`.
- `sdk/crypto/basic/crypto_keychain.hpp` declares format loading/writing, family-specific construction, and OpenSSL key encoding/decoding entry points. Implementations are split among `crypto_keychain.cpp` and family files such as `crypto_keychain_ec.cpp`, `crypto_keychain_rsa.cpp`, and `crypto_keychain_ossl3.cpp`.
- `sdk/crypto/basic/crypto_keygen.hpp` declares the parameter builder and generation interface; `crypto_keygen.cpp` handles parameter collection and dispatch, while `crypto_keygen_*` files implement family-specific paths.
- `sdk/crypto/basic/crypto_keyexchange.hpp` declares group-level exchange operations. `crypto_keyexchange.cpp` coordinates component key generation, share extraction, exchange, encapsulation, and decapsulation.
- `sdk/crypto/basic/evp_pkey.hpp` and OpenSSL wrapper types provide lower-level key-type recognition and resource wrappers.
- `sdk/crypto/advisor/crypto_advisor.hpp` maps algorithm identifiers, NIDs, key types, JOSE/COSE labels, TLS groups, support flags, and component sizes. The advisor provides metadata for dispatch; it does not perform the cryptographic operation.
- `sdk/crypto/basic/sign/` and `sdk/crypto/basic/kdf/` consume key objects or key material for signature and derivation operations.
- `sdk/crypto/jose/` handles JOSE structures and operations. JWK conversion bridges standard JSON key representation and `crypto_key`; JWS/JWE processing decides how selected keys are used.
- `sdk/crypto/cose/` handles COSE structures and operations. COSE_Key conversion bridges CBOR key representation and `crypto_key`; COSE signing/encryption code owns the surrounding message processing.
- `sdk/net/tls/` owns TLS handshake flow and key-schedule integration. Its key-share extension path calls `crypto_keyexchange`; the key directory provides key material and group-level cryptographic operations.

### 4.2 The common representation boundary

```text
             JWK / COSE_Key
                    |
          format-specific conversion
                    |
                    v
  crypto_keychain / crypto_keygen / crypto_key
                    |
          +---------+----------+
          |                    |
          v                    v
    JOSE / COSE             TLS key share
  sign, verify, encrypt,    group keygen/share/
  decrypt, key agreement   exchange or KEM
          |                    |
          v                    v
  protocol message/result   shared secret
                               |
                               v
                       TLS key schedule
```

This is a conceptual boundary diagram, not a claim that all paths use the same conversion function. JOSE and COSE translate their own wire/data formats; TLS key shares are protocol-specific bytes described by the selected group. The common layer reuses key objects and cryptographic operations without making those external representations interchangeable.

### 4.3 Algorithm-family and EC representation map

```text
                     algorithm / NID
                           |
       +-------------------+--------------------+
       |          |        |        |           |
      RSA        EC       OKP      DH/DSA     ML-KEM/PQ
       |          |        |        |           |
    n,e,d      x,y,d     raw x,d  y,x,p,q,g  named provider
       |          |        |        |           |
       +----------+--------+--------+-----------+
                           |
                     crypto_keychain
                           |
                   family-specific builder
                           |
                        EVP_PKEY
                           |
                   crypto_key_object
                           |
                       crypto_key
```

EC and OKP share a convenience dispatch path, but their point/key representations remain different:

```text
EC coordinates (x,y) ---------> add_ec()
EC compressed (x, ysign) ------> add_ec_compressed()
EC uncompressed point bytes ---> add_ec_uncompressed()
OKP raw public/private bytes --> add_okp()
                                 ^
                    add_ec2() dispatches by NID
```

This diagram maps the construction interfaces; it does not imply that every family supports every `crypto_keygen::build()` parameter route. In particular, the OpenSSL 3 named-algorithm path and the empty ML-KEM/ML-DSA/SLH-DSA cases in the generic `build()` dispatcher must be treated separately.

### 4.4 Implementation entry points

The source files listed in §4.1 define the key object, key collection, key construction, key generation, and group exchange boundaries. The links in §4.2 and §4.3 are conceptual maps of those boundaries, not a substitute for the concrete contracts and limitations described in the Data Model and Behavior Model.

### 4.5 Local implementation documents
- [Crypto primitives](../README.md)
- [Crypto advisor](../../advisor/README.md)
- [JOSE](../../jose/README.md)
- [COSE](../../cose/README.md)
- [TLS](../../../net/tls/README.md)
- [Key testcases](../../../../test/testcase/crypto/key/README.md)

### 4.6 Source-test coverage map

The key testcase directory covers several distinct contracts rather than one undifferentiated “key support” claim:

- `testcase_crypto_key.cpp` — common key-object operations and selection.
- `testcase_keygen.cpp` — key-generation entry points.
- `testcase_keyexchange.cpp` — group-level key-share, exchange, encapsulation or decapsulation paths as represented by the cases.
- `testcase_curves.cpp` and `testcase_ec.cpp` — curve metadata and EC key operations.
- `testcase_der.cpp` — DER/key encoding and decoding paths.
- RSA/DSA, DH/FFDHE, HPKE and ML-KEM testcases — family-specific behavior and vectors.

These are source-level coverage references. They do not mean every algorithm/provider combination runs successfully in every build. In particular, post-quantum key generation and KEM paths depend on the OpenSSL version and provider capabilities described above.

## 6. References
- [RFC 7517 — JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517) — JWK key parameter names and representation.
- [RFC 8037 — CFRG Elliptic Curve Diffie-Hellman and Signatures in JOSE](https://www.rfc-editor.org/rfc/rfc8037) — OKP keys in JOSE.
- [RFC 7748 — Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748) — X25519 and X448 key agreement.
- [RFC 7919 — Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for TLS](https://www.rfc-editor.org/rfc/rfc7919) — named FFDHE groups.
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3 named groups, key shares, and key schedule.
- [RFC 9052 — CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052) — COSE structures and processing.
- [OpenSSL EVP_PKEY documentation](https://docs.openssl.org/3.0/man7/EVP_PKEY/) — OpenSSL's public-key object abstraction.
- [OpenSSL encoder context documentation](https://docs.openssl.org/3.5/man3/OSSL_ENCODER_CTX_new_for_pkey/) and [decoder context documentation](https://docs.openssl.org/3.5/man3/OSSL_DECODER_CTX_new_for_pkey/) — OpenSSL 3.x key encoding/decoding paths.
