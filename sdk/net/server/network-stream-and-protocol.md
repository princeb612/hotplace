## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Network stream and protocol interpretation

## 1. Role

`network_stream`, `network_protocol_group`, and `network_protocol` convert arbitrary transport reads into protocol-framed messages. This is the middle stage of the [network server pipeline](README.md): the socket supplies bytes, the session buffers them, and a protocol interpreter establishes message boundaries before the consumer callback receives completed data.

## 2. Data Model

### Raw input buffer

`network_stream::produce()` copies received bytes into a `network_stream_data` node and appends it to a protected queue. Nodes carry a byte buffer/size, optional UDP peer address, priority, linked-list pointer, and reference count. `consume()` detaches queued nodes so producer work can continue while consumer traversal proceeds.

```text
socket read / datagram
  -> network_session::produce()
  -> network_stream::produce()
  -> queued network_stream_data nodes
  -> protocol framing
```

### Protocol registry and interpreter

`network_protocol_group` maps `protocol_id()` values to registered interpreters. It can register/remove/find protocols and inspect buffered bytes to choose a protocol whose `is_kind_of()` accepts the prefix. `more_data` means that the available prefix is not yet sufficient to identify the protocol.

A `network_protocol` supplies the framing decision through `is_kind_of(bytes)` and `read_stream(bytes)`. Its state distinguishes complete data from conditions such as `more_data`, `forged`, `crash`, or `large`. Protocols may also assign priority and expose packet-size constraints. The generic `use_alpn()` implementation returns false; protocol-specific paths may use ALPN information.

## 3. Behavior Model

### From transport bytes to one or more messages

```text
network_session::_stream
  -> network_stream framing loop
  -> concatenate queued nodes into temporary stream
  -> network_protocol_group selects interpreter
  -> network_protocol::read_stream()
       complete  -> move one message to target (_request)
       more_data -> retain bytes and wait for additional input
       invalid / oversized -> discard invalid queued input
  -> consumer callback receives completed data
```

The framing loop can emit multiple messages from one read and retain an incomplete message across reads. A TCP read boundary is not an HTTP message boundary. For datagrams, the peer address must remain associated with the data while the relevant protocol/session handles it.

With an empty protocol group, `network_stream::write()` can copy data directly. With interpreters registered, the write path performs protocol framing and can emit one or more complete messages.

## 4. Relationships

- `network_stream.hpp/.cpp` — byte queues, data nodes, framing loop.
- `network_protocol.hpp/.cpp` and `network_protocol_group.hpp/.cpp` — protocol contract and registry.
- [Network server overview](README.md) — complete worker path.
- [Network server model](network-server-model.md) — producer/consumer orchestration.
- [Network session](network_session.md) — owns raw stream and drives consume.
- [HTTP protocol stack](../http/http-protocol-stack.md) — concrete protocol layers.
- `sdk/net/http/http1/` and `sdk/net/http/http2/` — TCP-stream protocol implementations; HTTP/3 additionally depends on QUIC and ALPN.
- `test/testcase/net/http/testvector_http2.cpp` and `testcase_http.cpp` — source-level framing examples.

## 5. References

No external references are currently listed.
