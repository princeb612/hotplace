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

# TLS/DTLS/QUIC session support

## 1. Role

This directory groups session-level responsibilities: TLS/DTLS session state, DTLS record arrangement/publication, QUIC session/stream state and packet publication, and SSLKEYLOG import/export. Some implementation files are physically in the parent `sdk/net/tls/` directory. The documentation grouping should not be mistaken for a single source directory or one common wire format.

## 2. Data Model

### Session state and direction

`tls_session` coordinates protocol progress but does not contain one monolithic state machine. It owns the aggregate session-status bitmask, direction-indexed `session_info` objects, a `tls_protection` object, scheduled handshake/extension work, and lazily created transport helpers.

Each `session_info` keeps the current handshake type/status for its direction, a protection-active flag, record counters indexed by `protection_space_t`, queued alerts, and keyed per-direction values. The direction lookup normalizes client-initiated and server-initiated bidirectional stream directions to the corresponding client/server direction entry. Record counters are not global: each protection space has its own counter.

The aggregate status bitmask, per-direction handshake status, protection-active flag, alert queue, scheduled handshake queue, and per-space record counters are separate state dimensions. They should not be collapsed into a single enum or one global record counter.

### Protection-owned state and intermediate data

`tls_protection` is associated with the session and retains the negotiated version/cipher suite, negotiation context, key/key-exchange objects, transcript-hash object, and named secret collection. The session tracks when and in which direction state advances; the protection object supplies transcript, key-schedule, Finished, and encryption/decryption operations.

| State / data | Owner | Representation |
|---|---|---|
| Aggregate status bitmask | `tls_session` | Session-wide status bits |
| Directional handshake type | `session_info` | Current handshake status for one direction |
| Protection-active flag | `session_info` | Per-direction boolean state |
| TLS/DTLS record counter | `session_info` | Counter indexed by protection space |
| QUIC packet-number ranges | `quic_session` | Packet-number state separated by QUIC packet-number space |
| Negotiated version/cipher suite | `tls_protection` / `protection_context` | Selected protocol and suite context |
| Transcript hash/checkpoint | `tls_protection` | Transcript digest state and named checkpoints |
| Derived secrets/key/IV | `tls_protection` | Named secret and directional protection material |
| DTLS record pool / fragments | DTLS arranger / publisher | Stored records and outgoing fragment representation |
| QUIC packet/frame layout | QUIC session / packet publisher | Packet and frame objects |
| Imported key-log entries | `sslkeylog_importer` | Secret records indexed by ClientHello random |
| Exported key-log line | `sslkeylog_exporter` | Label, ClientHello random, and secret value |

TLS record numbers, DTLS epoch/record sequence, DTLS handshake sequence, and QUIC packet numbers remain distinct sequence domains. The protection-space index is an organizing key for session counters; it does not make these wire-level numbering schemes equivalent.

## 3. Behavior Model

### Session state mutation points

- `update_session_status()` ORs a status bit into the aggregate session-wide bitmask, signals waiters, and invokes the optional change-status hook.
- `session_info::set_status()` stores the current handshake type for one direction.
- `begin_protection()` / `reset_protection()` toggle whether that direction applies record protection.
- The alert queue retains alert level/description pairs until the caller retrieves them.
- The scheduled handshake queue retains handshake references and invokes each item's scheduled work when `run_scheduled(dir)` is called.

These mutations affect different dimensions of session state; an aggregate notification does not itself mean that directional record protection has been activated.


### Quick map: state is several coordinated dimensions

```text
                     tls_session
                          |
           +--------------+----------------+
           |              |                |
      aggregate       client/server     tls_protection
      status bits     session_info      transcript + secrets
           |              |                |
     waiters/hooks    handshake status     derivation
                          |
                 protection-active flag
                          |
              record protection decision
                 /                    \
             TLS/DTLS                  QUIC
          record counter          packet-number space
```

These tracks are related but not interchangeable. An aggregate status notification does not itself prove handshake completion; a derived secret does not automatically activate protection; and TLS/DTLS record counters are not QUIC packet numbers.

### Session state and protection progression

~~~text
session type selected
  -> tls_session associates tls_protection
  -> handshake parser/handler builds or consumes typed messages
  -> negotiation context records offers and selected parameters
  -> handshake path advances directional status and session events
  -> tls_protection updates transcript / calculates protocol-specific values
  -> session_info protection flag and counters select active context
  -> TLS/DTLS record path OR QUIC packet path protects bytes
~~~

1. **Create the session boundary.** The session is constructed with a session type. The protection object is associated with the session, while composer, DTLS, and QUIC helpers are created on demand by the corresponding accessors.
2. **Process handshake messages.** Message parsing/construction provides typed fields. Handshake processing, not the mere existence of a message object, decides when to update negotiation state, set directional handshake status, schedule work, or set aggregate session-status bits.
3. **Notify session observers.** `update_session_status(status)` ORs the event into the aggregate bitmask, signals the session semaphore, and calls the optional status hook. This is an event notification mechanism; it does not itself validate or complete a handshake transition.
4. **Update transcript and derive material at protocol-defined points.** The handshake path supplies handshake bytes to the protection layer. The transcript hash is initialized from the negotiated cipher suite's hash and updated with protocol-appropriate handshake input. Calculation paths then derive TLS 1.2 master-secret/key-block material or TLS 1.3 staged secrets and Finished values when called by the handshake path.
5. **Select directional protection context.** The direction's `session_info` supplies the protection-active flag and counter for the selected protection space. TLS/DTLS record processing uses record-oriented context; QUIC uses packet-number-space and QUIC packet-protection context.
6. **Continue through the transport-specific adapter.** TLS emits/consumes TLS records; DTLS uses record fragmentation and receive arrangement; QUIC carries TLS handshake bytes in CRYPTO frames and application stream bytes in STREAM frames. These adapters do not share one record format.

### Transcript update is a protocol operation

The transcript hash is not updated by blindly hashing every network buffer. The handshake/session path chooses when the encoded handshake message enters the transcript. The protection implementation has a DTLS 1.3-specific branch that excludes the DTLS-only message-sequence/fragment reconstruction fields from the transcript input; other paths use their protocol-specific handshake representation. HelloRetryRequest and Finished handling require their defined transcript checkpoints/transforms.

### DTLS receive arrangement

```text
UDP datagram + peer address
  -> dtls_record_arrange::produce
  -> validate record header / version / length
  -> extract epoch + 48-bit sequence
  -> derive peer cookie
  -> insert into peer-scoped ordering pool
  -> discard stale records / bound buffered window
  -> consume next available record with epoch + sequence
  -> DTLS session/parser
```

The peer cookie isolates each sender's ordering state. The pool orders records that have arrived; it does not reconstruct missing records or replace handshake-flight retransmission. The bounded pool also prevents out-of-order arrivals from accumulating without limit. Record sequence ordering is distinct from the DTLS handshake message sequence.

### DTLS record publication

```text
handshake objects
  -> serialize handshake message bytes
  -> dtls_record_publisher
       session must be DTLS
       split oversized handshake bodies into fragments
       apply fragment / segment limits
       form DTLS record output
  -> output container or callback
  -> datagram send path (caller-owned)
```

The publisher constructs DTLS record bytes; it does not send the UDP datagram itself. Fragment size limits handshake-body slices, while segment/grouping rules determine how serialized fragments are grouped into output records. A successful callback means local output was built and handed off, not that a peer received it.

### Session state, protection, and transport output

```text
record/handshake input
  -> handshake path advances tls_session protocol state
  -> transcript checkpoint / key schedule as required
  -> tls_protection directional state and secret material
  -> transport-specific protection inputs
       ├─ TLS/DTLS: record protection + record sequence context
       └─ QUIC: packet protection + packet-number-space context
  -> composer / publisher emits transport-specific wire units
```

This is a responsibility map, not a single unconditional call stack. Message-specific handshake processing decides when transcript and key-schedule operations occur; derived secrets, directional protection activation, and output construction are distinct steps. TLS/DTLS record counters and QUIC packet numbers remain separate sequence domains.

### QUIC packet publication

```text
TLS handshake message / frame input
  -> quic_packet_publisher (associated TLS/QUIC session)
  -> packet/frame layout
  -> QUIC packet builder
  -> packet-number-space + protection context
  -> packet protection
  -> callback receives packet bytes
  -> caller's UDP transport sends datagram
```

Handshake bytes are carried in CRYPTO frames; application and HTTP/3/QPACK stream bytes are carried in STREAM frames. The publisher lays out and protects packets for the relevant packet-number space, then hands the resulting bytes to its callback. UDP transmission, delivery, acknowledgement, and loss recovery are outside this callback boundary.

These adapters keep the wire formats separate: DTLS arranges and publishes DTLS records, whereas QUIC publishes protected QUIC packets. TLS handshake/key-schedule processing supplies protocol state and secrets but does not turn QUIC packets into TLS records.

### SSLKEYLOG import and export

The key-log helpers form an optional observation/import boundary around the session's named secrets; they are not part of the TLS wire protocol. The important setup distinction is that **export installs an output hook, while import installs a session-status hook and loads records before replaying the handshake**.

#### Export setup and call path

```text
caller / testcase initialization
  -> sslkeylog_exporter::get_instance()
  -> set(line_callback)
       e.g. write each line to a controlled log sink
  -> TLS handshake/key schedule calculates named secrets
  -> tls_protection calculation calls exporter->log(session, secret)
  -> exporter maps tls_secret_t to SSLKEYLOGFILE label
  -> "LABEL CLIENT_RANDOM_HEX SECRET_HEX"
  -> line_callback
```

For example, `test/testcase/tls/sample.cpp` installs a logger-backed callback when the `-k` option is supplied. In `DEBUG` builds, enabling the relevant trace level also installs that callback for the normal testcase path. The exporter itself is a singleton and does not open a file or register a callback with OpenSSL: `set()` stores the caller's callback, and the hotplace TLS protection calculation explicitly calls `log(session, secret)` when supported secrets are derived.

The current calculation call sites export TLS 1.3 client/server handshake traffic secrets, client/server application traffic secrets and exporter master secret, and the TLS 1.2 master secret. The exporter maps those values to the corresponding supported labels. It does not emit every label listed in the source comments; for example, merely having an early-traffic secret in session state does not mean this exporter currently serializes it.

#### Import setup and replay path

```text
PCAP SIMPLE testcase vector
  -> create tls_session (TLS or DTLS)
  -> sslkeylog_importer::clear()
  -> sslkeylog_importer::attach(&session)
       -> use_pre_master_secret(true)
       -> set_hook_change_session_status(session_status_changed)
  -> add each "LABEL CLIENT_RANDOM_HEX SECRET_HEX" line
       -> decode and index by ClientHello random + tls_secret_t
  -> replay records in vector order through dump_record(...)
  -> ClientHello status event
       -> find secrets by session ClientHello random
       -> assign matched values into tls_protection secrets
  -> later handshake/record processing consumes imported values
```

The concrete caller is `test/testcase/tls/testvector_pcap.cpp`. For each YAML vector it creates a fresh session, clears the importer's accumulated entries, attaches the importer, parses the vector's `secrets` sequence, and then feeds the listed records to `dump_record()`. The order matters: the importer must be attached to that session, and the key-log entries must be loaded before the relevant ClientHello status event occurs during replay.

`add()` accepts exactly three space-delimited columns: label, hexadecimal ClientHello random, and hexadecimal secret. The label must be in the importer's known-label table; unknown labels and malformed lines are rejected. The decoded secret is stored under the decoded ClientHello random and its mapped `tls_secret_t`. When the session reports the exact `session_status_client_hello` event, the hook reads the session's ClientHello random and assigns the matching named secrets into `tls_protection`. Parsing a line alone does not alter an arbitrary session, and a random mismatch means the entry will not be matched to that session.

#### Responsibilities and limits

- **Exporter:** `set(callback)` controls where emitted lines go; `log(session, secret)` formats a supported in-memory secret as a line. It does not perform handshake progression or derive the secret.
- **Importer:** `add(line)` parses/indexes external values; `attach(session)` enables pre-master-secret use and registers the status hook that installs matching values into the session. It does not synthesize missing key-log entries or independently decrypt a capture.
- **Session/protection:** handshake processing still controls status transitions, transcript handling, key derivation, and record/packet processing. Key-log import/export is a side channel around those operations, not a replacement for them.

The importer's accepted label table currently covers `CLIENT_RANDOM`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, and `EXPORTER_SECRET`. Do not infer support for labels that are not mapped in its source.

Key-log lines contain master secrets or traffic secrets that may permit decryption of captured traffic. A hook or imported key-log file must be treated as sensitive material and kept out of ordinary logs, bug reports, and public test artifacts unless the values are intentionally synthetic.

### Scope and interpretation

The session's status bitmask, directional handshake status, protection-active flag, transcript state, and sequence counters evolve at different call sites. A status bit being set does not alone prove that a peer handshake is complete; a successful encryption call does not prove delivery; and the presence of derived secrets does not mean every direction or protection space is active. Read state changes alongside the caller that triggers them.

### Real-code example: session status is not one boolean

The TLS 1.2 AEAD testcase in `test/testcase/tls/testcase_tls12_aead.cpp` demonstrates a narrow protection operation through `tls_session::get_tls_protection()`. For lifecycle behavior, follow the handshake/session path from `test/applet/tlsserver/run_server.cpp`; the applet selects the backend and runs a real connection, while the session maintains directional handshake/protection state and scheduled work.

```text
handshake processing -> per-direction session status
                    -> protection enabled for that direction
                    -> record processing uses active protection state
```

Do not interpret a session-wide status notification as proof that both directions have entered protected application-data state. Use the detailed state transitions in this document to interpret the integration trace.

## 4. Relationships
- `tls_session.hpp/.cpp`, `dtls_record_arrange.hpp/.cpp`, `dtls_record_publisher.hpp/.cpp`.
- `quic_packet_publisher.hpp/.cpp`, `quic_session.hpp/.cpp`, `quic_streams.hpp/.cpp`.
- `sslkeylog_exporter.hpp/.cpp`, `sslkeylog_importer.hpp/.cpp`.
- [TLS protection](../protection/README.md) — transcript hashing, key schedule and protection.
- [TLS protection/session flow](../tls-protection-and-session.md) — message-specific transcript updates, Finished scheduling, and directional protection transitions.
- [QUIC packet/frame](../quic/README.md) — packet/frame encoding and CRYPTO integration.
- [TLS advisor](../advisor/README.md) — protocol identifier and parameter hints.
- [DTLS record arrangement](dtls_record_arrange.md), [DTLS record publisher](dtls_record_publisher.md), [QUIC packet publisher](quic_packet_publisher.md).
- `test/testcase/tls/` and `test/testcase/quic/sample.cpp` — source-level protocol/trace paths.

## 5. References
- [RFC 6347 — DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
