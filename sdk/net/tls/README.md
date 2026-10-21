## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1105                  │
│ Documentation scope: protocol layers         │
└──────────────────────────────────────────────┘
```
# TLS, DTLS, and QUIC

## 1. Role

`sdk/net/tls` contains hotplace's TLS, DTLS, and QUIC-related protocol machinery. It includes TLS records, handshake messages and extensions, session/protection state, DTLS record fragmentation and arrangement, and QUIC packets/frames with TLS 1.3 handshake integration.

This directory is not just a collection of RFC notes. The implementation represents protocol messages and state, serializes or parses their wire forms, and coordinates security/session operations. Keep protocol requirements from the RFCs distinct from the exact subset and behavior implemented by hotplace.

## 2. Data Model

The local implementation is organized around protocol units, session state, and construction helpers. The hierarchy below is a text map of the main object families, not a claim that every class participates in every connection.

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

The protocol families share selected session and cryptographic concepts, but QUIC packets/frames are not TLS records. QUIC integrates TLS handshake and key-schedule behavior while carrying handshake bytes through QUIC CRYPTO frames.

## 3. Behavior Model

### Session and protection state

The session/protection layer owns state that spans individual messages: negotiated parameters, handshake progress, transcript/key-schedule material, and record-protection context. A record or handshake object represents a particular protocol unit; it should not be mistaken for the lifetime owner of the entire secure connection. Use the [protection/session model](tls-protection-and-session.md) for the detailed state boundary and [TLS message model](tls-message-model.md) for record/handshake/extension construction.

### DTLS record publication and arrangement

DTLS uses datagrams, so one handshake flight may need fragmentation and received records may arrive out of sequence. The source exposes two complementary responsibilities:

- `dtls_record_publisher` publishes records from a record/handshake representation and supports a fragment-size setting and an option to place multiple handshakes in a record.
- `dtls_record_arrange` accepts incoming datagram data and maintains packet state grouped by peer cookie/address and epoch/sequence information so records can be consumed in order.

These components solve opposite sides of the datagram boundary: publication adapts outbound protocol data to record/fragment limits; arrangement makes inbound records available in the required order. They are associated with `tls_session`, so they should be explained as session facilities rather than unrelated standalone utilities.

### QUIC packet publication

`quic_packet_publisher` works at a different wire boundary. It combines QUIC packet/frame material with TLS handshake messages through QUIC CRYPTO-related processing, supports payload-size and packet flags, and publishes packet bytes through a callback/container. Its payload-size setting is not equivalent to DTLS record fragment size: the two publishers operate on different protocol units and overhead rules.

### Shared session abstraction, distinct wire units

```text
TLS session
  └─ TLS record / handshake / extension

DTLS session
  ├─ record publisher: handshake/record → datagram-sized output
  └─ record arranger: datagram input → ordered record data

QUIC session
  └─ packet publisher: handshake/frame material → QUIC packet output
```

This diagram shows the shared session association and distinct publication boundaries. It does not mean that QUIC carries ordinary TLS records: QUIC integrates TLS handshake/key-schedule behavior while carrying handshake bytes through QUIC's own packet/frame transport.

### Compatibility and implementation boundary

The directory's topic map includes multiple TLS/DTLS generations and QUIC features. The presence of a class or RFC reference does not establish full conformance to every version or extension. Confirm capability claims against the concrete implementation, build guards, and relevant testcase assertions.

## 4. Relationships



- [TLS advisor implementation](tls_advisor.md)
- [DTLS record arrangement](dtls_record_arrange.md)
- [DTLS record publisher](dtls_record_publisher.md)
- [QUIC packet publisher](quic_packet_publisher.md)
- [Protection and session](protection/README.md) and [session model](session/README.md) — connection-spanning state and record protection.
- [TLS message model](tls-message-model.md) — record, handshake, and extension representations.
- [QUIC integration](quic/README.md) and [QUIC/TLS integration model](quic-tls-integration.md) — packet/frame transport and TLS 1.3 handshake integration.
- [TLS advisor](advisor/README.md) — identifier and parameter mapping for protocol choices.
- `sdk/crypto/` — cryptographic primitives, key operations, signatures, digests and KDF support.
- `sdk/net/basic/` — socket/secure-socket integration beneath protocol processing.
- `sdk/net/http/` — HTTP/2 and HTTP/3 consumers above the relevant transport path.
- `test/testcase/tls/` — source-level test entry points and protocol test vectors.

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

### RFC figures transcribed as plain text

The following text diagrams are retained as quick-reading aids. The authoritative wording and any corrections should be checked against the linked RFCs.

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

## 6. Developer Notes

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
- Local implementation documents belong under [Relationships](#4-relationships), not under external References.
