## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1107                  │
│ Documentation scope: protocol layers         │
└──────────────────────────────────────────────┘
```
# TLS, DTLS, and QUIC

## 1. Role

`sdk/net/tls` contains hotplace's TLS, DTLS, and QUIC-related protocol machinery. It includes TLS records, handshake messages and extensions, session/protection state, DTLS record fragmentation and arrangement, and QUIC packets/frames with TLS 1.3 handshake integration.

This directory is not just a collection of RFC notes. The implementation represents protocol messages and state, serializes or parses their wire forms, and coordinates security/session operations. Keep protocol requirements from the RFCs distinct from the exact subset and behavior implemented by hotplace.

## 2. Data Model

The directory is best understood as three connected kinds of state: protocol-message objects, connection/session state, and cryptographic state. This map is conceptual; a QUIC connection does not pass through the TLS record layer.

~~~text
Logical message objects
  tls_handshake(s)
    ├─ message-specific fields
    └─ tls_extensions -> typed extension values

Transport/wire objects
  TLS  -> tls_record(s)
  DTLS -> DTLS records + epoch/record-sequence state
  QUIC -> packets / frames + packet-number-space state

tls_session
  ├─ aggregate status + per-direction session_info
  ├─ tls_protection
  │    ├─ negotiated version / cipher suite
  │    ├─ negotiation context
  │    ├─ transcript hash
  │    └─ derived secrets / key material
  └─ transport helpers
       ├─ TLS composer
       ├─ DTLS record publisher / arranger
       └─ QUIC session / packet publisher

tls_advisor -> protocol metadata
crypto_advisor -> primitive-level metadata
~~~

### Protocol object inventory

The following tree is a quick inventory of representative protocol objects and message families implemented in this directory. It is a navigation aid, not an exhaustive list of every RFC-defined message or a claim that every feature is fully supported.

```text
TLS / DTLS
  tls_session
    ├─ tls_protection
    ├─ tls_record
    │    ├─ alert / application_data / change_cipher_spec
    │    ├─ handshake
    │    └─ record collections and builders
    ├─ tls_handshake
    │    ├─ ClientHello / ServerHello / Finished
    │    ├─ Certificate / CertificateVerify
    │    ├─ key exchange and session-ticket messages
    │    └─ handshake collections and builders
    └─ tls_extension
         ├─ key_share / pre_shared_key / supported_versions
         ├─ signature_algorithms / supported_groups
         ├─ SNI / ALPN / status_request
         └─ extension collections and builders

QUIC
  quic_packet
    ├─ Initial / Handshake / 0-RTT / 1-RTT
    ├─ Retry / Version Negotiation
    └─ packet builder
  quic_frame
    ├─ ACK / CRYPTO / PADDING / PING
    ├─ stream-control and connection-close frames
    └─ frame collections and builders
```

The TLS/DTLS tree groups session-associated record, handshake, and extension representations. QUIC is shown separately because it protects packets and carries TLS handshake bytes in CRYPTO frames rather than passing through the TLS record layer.

### Principal state and data ownership

- **Negotiation context:** offered and selected cipher suites, signature schemes, supported groups and versions, EC point formats, and key-share groups. The `protection_context` represents negotiation parameters; it is not the cryptographic key store.
- **Transcript state:** protocol-defined handshake input and its digest/checkpoints. This state is distinct from transport bytes, record headers, and the serialized message objects that supplied the handshake input.
- **Protection material:** master secret and key-block fields for TLS 1.2; staged secrets and directional traffic key/IV material for TLS 1.3; QUIC Initial and TLS-derived QUIC key/IV/header-protection material. These are different state classes with different derivation inputs.
- **Independent sequence state:** TLS record sequence numbers, DTLS epoch/record-sequence pairs, and QUIC packet numbers grouped by packet-number space. They are not one shared connection counter.
- **Pending output:** DTLS record fragments and QUIC queued handshake/frame/stream content are intermediate representations owned by their publication paths, not yet serialized wire units.

The objects above are related through the session/protection boundary, but they are not interchangeable. Session state tracks handshake progress and directional status; protection state retains negotiation, transcript, and key-schedule data; transport helpers maintain the record/packet-specific state required by their wire format.

## 3. Behavior Model

### Quick architecture map

Read this map top-down to locate a responsibility before opening the detailed sections.

```text
                  TLS / DTLS / QUIC session
                             |
              +--------------+--------------+
              |                             |
       handshake messages              negotiated state
       + extensions                   version / suite / group
              |                             |
              +-------------+---------------+
                            |
                    tls_protection
              transcript / key schedule
                /            |            \
               /             |             \
        TLS 1.2 keys    TLS 1.3 secrets    QUIC Initial
        + key block     + traffic keys    salt + DCID
               \             |             /
                \            |            /
                 +-----------+-----------+
                             |
                 +-----------+-----------+
                 |           |           |
              TLS record  DTLS record  QUIC packet
              sequence    epoch + seq  packet number
              AEAD/CBC    datagram     AEAD + HP
                 |           |           |
                TCP          UDP         UDP
```

**Boundary to remember:** TLS and DTLS use record protection; QUIC uses packet protection. TLS handshake bytes enter QUIC through CRYPTO frames, not through TLS records. The three sequence-number domains are independent.


### State and data transformation overview

```text
handshake message / extension objects
        |
        v
negotiation context -----> selected version / suite / group
        |                               |
        v                               v
handshake transcript ----------> key schedule / traffic secrets
                                        |
                    +-------------------+------------------+
                    |                   |                  |
                    v                   v                  v
              TLS record state   DTLS epoch/sequence   QUIC packet space
                    |                   |                  |
                    v                   v                  v
              record protection   fragment/arrange     packet + frame
                    |                   |                  |
                    v                   v                  v
                 TCP bytes          UDP datagrams       UDP datagrams
```

This flow describes data dependencies, not a single shared wire format. TLS and DTLS protect records; QUIC protects packets, and carries TLS handshake bytes in CRYPTO frames rather than TLS records.

### Negotiation to protected traffic

1. **Build or parse message objects.** Record classes frame content; handshake classes encode/decode typed messages; extension classes hold typed extension payloads. A message collection can contain multiple handshakes, and record framing is distinct from the handshake message header.
2. **Resolve identifiers.** Handshake/session code reads cipher-suite, extension, group, signature-scheme, version, or QUIC identifiers. tls_advisor returns metadata from its resource tables; crypto_advisor supplies lower-level algorithm/key metadata. A known hint is not proof that the full algorithm path is usable in every build.
3. **Negotiate and retain state.** protection_context collects offered parameters and chooses a compatible version/cipher suite/group according to the session negotiation path. The result is retained by tls_protection and session status/configuration; message objects alone do not represent handshake progress.
4. **Advance transcript and derive material.** As the handshake advances, protocol-defined handshake bytes feed the transcript hash. TLS 1.2 calculation paths derive the master secret/key block; TLS 1.3 paths derive stage-specific secrets and traffic key/IV values. HelloRetryRequest and PSK/early-data branches change which transcript checkpoint and derivation inputs apply.
5. **Protect the correct wire unit.** TLS/DTLS record paths construct the appropriate record context and encrypt/authenticate content. QUIC Initial protection derives from its version-specific salt and destination connection ID, while Handshake/Application protection uses TLS-derived secrets; packet-number-space-specific AEAD and header protection are applied to QUIC packets. The cryptographic material is shared by purpose, not by wire format.
6. **Adapt to transport boundaries.** DTLS publication fragments oversized handshake bodies and segments records for datagram output; the receive arranger validates datagram records and buffers them by peer and epoch/sequence until the next expected record is available. QUIC publication maps TLS handshakes to CRYPTO frames and application/HTTP/3/QPACK content to STREAM frames, then packs frames into packets within a payload target.
7. **Return output to the caller.** Publisher callbacks or output containers receive serialized protocol units. Socket transmission, retransmission/loss recovery, and full peer interoperability are separate responsibilities and should not be inferred merely from a successful serialization path.

### Concrete record-protection path from `testcase_tls12_aead.cpp`

The TLS 1.2 AES-128-GCM testcase isolates record protection using captured-session inputs rather than running a complete client/server handshake:

```text
fixed TLS 1.2 cipher suite (0xc02b)
  + client_random + server_random + master_secret
                    |
                    v
protection.calc_keyblock(SHA-256, master_secret, randoms, suite)
                    |
                    +--> compare derived client_write_key / client_write_IV
                    |
                    v
captured TLS record bytes
  -> protection.decrypt(session, from_client, record, sequence=0)
  -> check operation status
```

The testcase compares the derived client key and IV against fixed expected bytes before attempting decryption. The record includes the TLS record header and encrypted payload/tag, and the direction selects the client-side traffic material. This is a focused known-input record-protection test: it does not exercise negotiation, certificate validation, or a full handshake. In the shown code the decrypt result is checked for success, but the resulting plaintext is not compared against an expected byte sequence, so do not describe this particular assertion as a plaintext known-answer check.

### Session lifecycle and state boundaries

tls_session owns the tls_protection object and lazily creates the relevant composer/publisher/arranger/session helpers. Each direction has its own session_info, including handshake status, protection activation, alert queue, and record-number state keyed by protection space. DTLS and QUIC helpers are session-associated because their decisions depend on negotiated state and transport-specific numbering.

The shared abstraction is therefore **session and cryptographic state**, not a shared record format:

~~~text
TLS:  handshake → TLS record → TLS record protection → stream transport
DTLS: handshake → DTLS fragmentation/record → datagram transport
                 receive: datagram → validate/order records → session
QUIC: handshake → CRYPTO frame ─┐
       app/HTTP3/QPACK → STREAM ├→ QUIC packet protection → UDP datagram
                                ┘
~~~

### Implementation boundary

These flows describe responsibilities visible in source. The presence of a message class, hint, RFC note, or construction test does not establish complete conformance to every TLS/DTLS version or QUIC feature. Keep protocol requirements, implemented code paths, and actually executed test evidence separate.

### Real-code entry points: isolate crypto from integration

There are two complementary ways to study the TLS path:

- **Focused record protection:** `test/testcase/tls/testcase_tls12_aead.cpp` creates a `tls_session`, selects TLS 1.2 and cipher suite `0xc02b`, derives the key block from fixed randoms and a master secret, checks the expected client key/IV, then attempts to decrypt a captured record. This isolates key derivation and record protection without running negotiation or certificate validation.
- **End-to-end socket integration:** `test/applet/tlsserver/run_server.cpp` chooses TLS version/backend flags, builds the server socket, and uses `network_server` callbacks to echo application data. The handshake and record operations are performed below the callback by the selected backend/session path.

```text
focused testcase:
fixed inputs -> tls_protection key block -> expected key/IV checks -> record decrypt

server applet:
options -> server_socket_builder -> network_server -> TLS session/handshake
        -> completed application data -> consumer callback -> session.send()
```

Use the testcase when reasoning about cryptographic inputs and outputs; use the applet when reasoning about negotiation, socket integration, and application-data flow. Neither example alone proves complete protocol conformance: the testcase is not a full handshake, and a successful applet run covers only the exercised backend/options/peer combination.
## 4. Relationships
- [TLS/QUIC advisor](advisor/README.md) — protocol identifiers, resource indexes, and cross-advisor metadata mapping.
- [DTLS record arrangement](session/dtls_record_arrange.md)
- [DTLS record publisher](session/dtls_record_publisher.md)
- [QUIC packet publisher](session/quic_packet_publisher.md)
- [Protection and session](protection/README.md) and [session model](session/README.md) — connection-spanning state and record protection.
- [TLS key schedule](protection/tls_key_schedule.md), [transcript hash](protection/tls_transcript_hash.md), and [MtE vs EtM](protection/tls_mte_etm.md) — focused implementation/study notes for the cryptographic stages described in the protection overview.
- [Protection/session flow](tls-protection-and-session.md) — source call order for transcript checkpoints, Finished verification, derivation, and directional activation.
- [QUIC/TLS integration](quic-tls-integration.md) — TLS handshake bytes and derived secrets crossing into QUIC CRYPTO frames and packet protection.
- `sslkeylog_importer` / `sslkeylog_exporter` in `session/` — optional key-log import/export hooks for named session secrets; key-log material is sensitive.
- [TLS message model](tls-message-model.md) — record, handshake, and extension representations.
- [QUIC integration](quic/README.md) and [QUIC/TLS integration model](quic-tls-integration.md) — packet/frame transport and TLS 1.3 handshake integration.
- [TLS advisor](advisor/README.md) — identifier and parameter mapping for protocol choices.
- `sdk/crypto/` — cryptographic primitives, key operations, signatures, digests and KDF support.
- `sdk/net/basic/` — socket/secure-socket integration beneath protocol processing.
- `sdk/net/http/` — HTTP/2 and HTTP/3 consumers above the relevant transport path.
- `test/testcase/tls/` — source-level test entry points and protocol test vectors.
- `test/testcase/quic/` — QUIC packet/number/protection vectors and PCAP SIMPLE paths; see its testcase README for explicit source-level and runtime-evidence boundaries.

## 5. References
### Protocol specifications

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 6347 — Datagram Transport Layer Security 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9147 — Datagram Transport Layer Security 1.3](https://www.rfc-editor.org/rfc/rfc9147)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)

### Online resources

- [TLS 1.3 Illustrated](https://tls13.xargs.org/)
- [TLS 1.2 Illustrated](https://tls12.xargs.org/)
- [DTLS Illustrated](https://dtls.xargs.org/)
- [QUIC Illustrated](https://quic.xargs.org/)
- [Cipher suite information](https://ciphersuite.info/cs/)
- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)

## 6. Developer Notes

### RFC figures transcribed as plain text

The following diagrams are retained as quick-reading aids. The authoritative wording and any corrections should be checked against the linked RFCs.

#### RFC 8446 Figure 1: Message Flow for Full TLS Handshake
````
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.

               Figure 1: Message Flow for Full TLS Handshake
````

#### RFC 8446 Figure 2: Message Flow for a Full Handshake with Mismatched Parameters
````
        Client                                               Server

        ClientHello
        + key_share             -------->
                                                  HelloRetryRequest
                                <--------               + key_share
        ClientHello
        + key_share             -------->
                                                        ServerHello
                                                        + key_share
                                              {EncryptedExtensions}
                                              {CertificateRequest*}
                                                     {Certificate*}
                                               {CertificateVerify*}
                                                         {Finished}
                                <--------       [Application Data*]
        {Certificate*}
        {CertificateVerify*}
        {Finished}              -------->
        [Application Data]      <------->        [Application Data]

             Figure 2: Message Flow for a Full Handshake with
                           Mismatched Parameters
````

#### RFC 8446 Figure 3: Message Flow for Resumption and PSK
````

          Client                                               Server

   Initial Handshake:
          ClientHello
          + key_share               -------->
                                                          ServerHello
                                                          + key_share
                                                {EncryptedExtensions}
                                                {CertificateRequest*}
                                                       {Certificate*}
                                                 {CertificateVerify*}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Certificate*}
          {CertificateVerify*}
          {Finished}                -------->
                                    <--------      [NewSessionTicket]
          [Application Data]        <------->      [Application Data]


   Subsequent Handshake:
          ClientHello
          + key_share*
          + pre_shared_key          -------->
                                                          ServerHello
                                                     + pre_shared_key
                                                         + key_share*
                                                {EncryptedExtensions}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Finished}                -------->
          [Application Data]        <------->      [Application Data]

               Figure 3: Message Flow for Resumption and PSK
````

#### RFC 8446 Figure 4: Message Flow for a 0-RTT Handshake
````
         Client                                               Server

         ClientHello
         + early_data
         + key_share*
         + psk_key_exchange_modes
         + pre_shared_key
         (Application Data*)     -------->
                                                         ServerHello
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                                       + early_data*
                                                          {Finished}
                                 <--------       [Application Data*]
         (EndOfEarlyData)
         {Finished}              -------->
         [Application Data]      <------->        [Application Data]

               +  Indicates noteworthy extensions sent in the
                  previously noted message.

               *  Indicates optional or situation-dependent
                  messages/extensions that are not always sent.

               () Indicates messages protected using keys
                  derived from a client_early_traffic_secret.

               {} Indicates messages protected using keys
                  derived from a [sender]_handshake_traffic_secret.

               [] Indicates messages protected using keys
                  derived from [sender]_application_traffic_secret_N.

               Figure 4: Message Flow for a 0-RTT Handshake

````
#### RFC 9147 Figure 2: DTLS 1.3 Record Formats
````
       struct {
           ContentType type;
           ProtocolVersion legacy_record_version;
           uint16 epoch = 0
           uint48 sequence_number;
           uint16 length;
           opaque fragment[DTLSPlaintext.length];
       } DTLSPlaintext;

       struct {
            opaque content[DTLSPlaintext.length];
            ContentType type;
            uint8 zeros[length_of_padding];
       } DTLSInnerPlaintext;

       struct {
           opaque unified_hdr[variable];
           opaque encrypted_record[length];
       } DTLSCiphertext;

                     Figure 2: DTLS 1.3 Record Formats
````
#### RFC 9147 Figure 3: DTLS 1.3 Unified Header
````
       0 1 2 3 4 5 6 7
       +-+-+-+-+-+-+-+-+
       |0|0|1|C|S|L|E E|
       +-+-+-+-+-+-+-+-+
       | Connection ID |   Legend:
       | (if any,      |
       /  length as    /   C   - Connection ID (CID) present
       |  negotiated)  |   S   - Sequence number length
       +-+-+-+-+-+-+-+-+   L   - Length present
       |  8 or 16 bit  |   E   - Epoch
       |Sequence Number|
       +-+-+-+-+-+-+-+-+
       | 16 bit Length |
       | (if present)  |
       +-+-+-+-+-+-+-+-+

                     Figure 3: DTLS 1.3 Unified Header
````
#### RFC 9147 Figure 4: DTLS 1.3 Header Examples
````
    0 1 2 3 4 5 6 7       0 1 2 3 4 5 6 7       0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+
   | Content Type  |     |0|0|1|1|1|1|E E|     |0|0|1|0|0|0|E E|
   +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+
   |   16 bit      |     |               |     |8 bit Seq. No. |
   |   Version     |     / Connection ID /     +-+-+-+-+-+-+-+-+
   +-+-+-+-+-+-+-+-+     |               |     |               |
   |   16 bit      |     +-+-+-+-+-+-+-+-+     |   Encrypted   |
   |    Epoch      |     |    16 bit     |     /   Record      /
   +-+-+-+-+-+-+-+-+     |Sequence Number|     |               |
   |               |     +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+
   |               |     |   16 bit      |
   |   48 bit      |     |   Length      |       DTLSCiphertext
   |Sequence Number|     +-+-+-+-+-+-+-+-+         Structure
   |               |     |               |         (minimal)
   |               |     |  Encrypted    |
   +-+-+-+-+-+-+-+-+     /  Record       /
   |    16 bit     |     |               |
   |    Length     |     +-+-+-+-+-+-+-+-+
   +-+-+-+-+-+-+-+-+
   |               |      DTLSCiphertext
   |               |        Structure
   /   Fragment    /          (full)
   |               |
   +-+-+-+-+-+-+-+-+

    DTLSPlaintext
      Structure

                     Figure 4: DTLS 1.3 Header Examples
````


### Key exchange and key-schedule calculation notes

#### summarize the complex calculation process

|                     |         |                           |
| --                  | --      | --                        |
| client_key_exchange | TLS 1.2 | pre-master secret         |
| key_share           | TLS 1.3 | ECDHE                     |
| pre_shared_key      | TLS 1.3 | session-resumption, 0-RTT |

```
case client_hello
  case extension.key_share
    generate keypair
    send keypair.pubkey
  end
end

case server_hello
  case extension.key_share
    generate keypair
    send keypair.pubkey
    shared_secret = Diffie-Hellman(keypair.privkey, keypair.pubkey)
  end
  early_secret = Extract(hashalg, salt, empty_ikm)
  case 1-RTT, HRR:
    secret_handshake_derived = Expand-Label(hashalg, dlen, early_secret, "derived", empty_hash)
    secret_handshake = Extract(hashalg, secret_handshake_derived, shared_secret);
  case 0-RTT:
    secret_handshake_derived = Expand-Label(hashalg, dlen, secret_resumption_early, "derived", empty_hash)
    secret_handshake = Extract(hashalg, secret_handshake_derived, shared_secret);
  end
  secret_c_hs_traffic = Expand-Label(hashalg, dlen, secret, handshake, "c hs traffic", context_hash)
  secret_s_hs_traffic = Expand-Label(hashalg, dlen, secret, handshake, "s hs traffic", context_hash)
end

case certificate
  send certificate
end

case server_key_exchange
  case server:
    // signature algorithm (same kty of certificate)
    sign(certificate-privkey, client_hello_random + server_hello_random + curve_info + public_key)
  case client:
    verify(certificate, client_hello_random + server_hello_random + curve_info + public_key)
end

// client_key_exchange and then change_cipher_spec, encrypt and decrypt application_data
case client_key_exchange
  case client:
    generate keypair
    send keypair.pubkey
  case server:
    pre_master_secret = Diffie-Hellman(keypair.privkey, keypair.pubkey);
    // RFC 2246 5. HMAC and the pseudorandom function
    // RFC 2246 8.1. Computing the master secret
    master_secret = PRF(pre_master_secret, "master secret",
                        ClientHello.random + ServerHello.random)
                        [0..47];
    // RFC 2246 5. HMAC and the pseudorandom function
    // RFC 5246 5.  HMAC and the Pseudorandom Function
    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                           HMAC_hash(secret, A(2) + seed) +
                           HMAC_hash(secret, A(3) + seed) + ...
    A() is defined as:
        A(0) = seed
        A(i) = HMAC_hash(secret, A(i-1))
    PRF(secret, label, seed) = P_<hash>(secret, label + seed)
    // RFC 2246 5. HMAC and the pseudorandom function
    // RFC 2246 6.3. Key calculation
    key_block = PRF(SecurityParameters.master_secret,
                       "key expansion",
                       SecurityParameters.server_random +
                       SecurityParameters.client_random);
    client_write_MAC_secret[SecurityParameters.hash_size]
    server_write_MAC_secret[SecurityParameters.hash_size]
    client_write_key[SecurityParameters.key_material_length]
    server_write_key[SecurityParameters.key_material_length]
    client_write_IV[SecurityParameters.IV_size]
    server_write_IV[SecurityParameters.IV_size]
  end
end
```

- These notes are a compact working summary, not a complete or normative description of TLS key scheduling. Verify each version-specific step, label, context hash, and input against the relevant RFC and the implementation before using it to explain code behavior.
- Local implementation documents belong under [Relationships](#5-relationships), not under external References.
