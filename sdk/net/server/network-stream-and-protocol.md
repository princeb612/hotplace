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

# Network stream and protocol interpretation

## 1. Role

`network_stream`, `network_protocol_group`, and `network_protocol` convert arbitrary transport reads into protocol-framed messages. This is the middle stage of the [network server pipeline](README.md): the socket supplies bytes, the session buffers them, and a protocol interpreter establishes message boundaries before the consumer callback receives completed data.

## 2. Data Model

### Queued input node

`network_stream_data` owns a copied byte buffer and its size. It can also retain a peer address for datagrams, a priority value, a next pointer, and a reference-counted lifetime. `network_stream` owns the node queue and protects queue state with a critical section. The node representation keeps transport-read chunks and datagram peer metadata separate from protocol-message boundaries.

```text
network_stream
  └─ locked queue<network_stream_data>
       ├─ content + size (owned copy)
       ├─ optional sockaddr_storage_t (datagram peer)
       ├─ priority
       └─ reference-counted node lifetime
```

### Protocol registry and framing contract

`network_protocol_group` maps each `protocol_id()` to a protocol instance and protects registry operations with a lock. Adding a protocol retains a reference; lookup and protocol detection return referenced protocol objects that callers must release. `network_protocol` supplies the protocol-specific contract:

- `is_kind_of(prefix)` identifies whether the available bytes match a protocol, or whether more bytes are needed to identify it.
- `read_stream(buffer, message_size, state, priority)` determines the consumed message size and reports framing state.
- `set_constraints()/get_constraints()` carry generic constraints such as packet-size limits.
- `protocol_state_t` distinguishes states including `complete`, `more_data` via return status, `forged`, `crash`, and `large`.

The group is a registry/selector, not the parser itself. The selected protocol interprets the buffer and establishes message boundaries. The generic `use_alpn()` implementation returns false; protocol-specific implementations may override ALPN behavior.

## 3. Behavior Model

### Input accumulation

```text
network_session::produce(...)
  -> network_stream::produce(bytes, optional peer)
  -> allocate network_stream_data
  -> copy bytes and peer metadata
  -> append under queue lock
```

Each input event is stored as a node rather than being assumed to be a complete protocol message. This preserves the difference between transport read boundaries and application framing. Datagram peer identity travels with the node so later processing can associate the payload with its sender.

### Protocol selection and framing loop

```text
network_stream::read(protocol_group, target)
  -> source.write(protocol_group, target)
  -> concatenate queued node bytes into temporary basic_stream
  -> protocol_group.is_kind_of(prefix)
  -> selected network_protocol::read_stream(...)
       complete -> copy one message to target
       more_data -> wait for additional input / retain remainder
       forged, crash, large -> clear queued invalid input
  -> continue while another complete message is available
```

When the protocol group is empty, `do_write()` transfers queued nodes directly to the target stream. With registered protocols, `do_writep()` walks the queue in order and appends each node's bytes to a temporary `basic_stream`. After each append it asks `network_protocol_group::is_kind_of()` to select an interpreter. Once an interpreter is selected, its `read_stream()` reports a protocol state and the number of bytes belonging to the first complete unit.

For `protocol_state_t::complete`, the whole framed unit is copied to the target with `target->produce(bufstream.data(), message_size, ...)`. Queue consumption is then reconciled against that byte count:
- Nodes wholly before the message boundary are released and erased.
- If the boundary lands exactly at a node boundary, that node is removed; if later nodes remain, `do_writep()` returns `more_data` so the caller can frame the next unit in the same pass.
- If the boundary falls inside a node, the bytes after `message_size` are copied from the concatenated `bufstream` back into that node, its priority is updated from the protocol result, and `more_data` requests another framing pass. Later nodes remain queued.

This means the queue does not merely pop the node that completed protocol recognition: it consumes exactly the reported prefix across the node sequence and preserves the suffix for subsequent framing. An incomplete prefix/state leaves the queued bytes in place for a later producer pass. `forged`, `crash`, and `large` release and clear the queued input. If protocol identification returns an error other than success or `more_data`, the nodes examined in that pass are removed. This permits one read to yield several framed units and one unit to span several reads.

### Incomplete and invalid input

An insufficient prefix can return `more_data`, so the stream retains input until another producer pass appends bytes. When the selected protocol marks the input `forged`, `crash`, or `large`, the current queued input is released and cleared. These states are protocol framing outcomes; the multiplexer itself does not inspect or validate message structure.

### Output and callback boundary

Completed messages are copied into the target stream, which is the session's `_request` stream in the normal server path. The consumer callback receives the completed data and session context after framing. Protocol parsing is therefore separate from application dispatch: HTTP handlers consume HTTP-framed messages, while the generic network layer remains responsible for transport buffering and protocol selection.

### Real-code example: why callback input is not a socket read

`test/applet/httpserver1/run_server.cpp` consumes an already assembled `http_request`; it does not treat `data_array[1]` as an entire HTTP message. The network stream buffers input, asks the protocol group to identify the framing adapter, and consumes only complete messages while retaining incomplete or trailing bytes.

```text
socket read events -> queued network_stream_data nodes
  -> protocol-group selection
  -> protocol read_stream / message-size result
  -> consume complete message bytes
  -> preserve incomplete/trailing bytes
  -> application callback with completed request
```

Use `test/applet/tcpserver2/run_server.cpp` as the contrasting raw echo path: there the callback intentionally works with received bytes rather than an HTTP message object.

## 5. Relationships
- `network_stream.hpp/.cpp` — queue nodes, byte accumulation, and framing loop.
- `network_protocol.hpp/.cpp` and `network_protocol_group.hpp/.cpp` — protocol contract, registry, and selector.
- [Network server overview](README.md) — complete worker path.
- [Network server execution model](network-server-model.md) — producer/consumer orchestration.
- [Network session](network_session.md) — owns raw stream and drives consume.
- [HTTP protocol stack](../http/http-protocol-stack.md) — concrete protocol layers.
- `sdk/net/http/http1/` and `sdk/net/http/http2/` — TCP-stream protocol implementations; HTTP/3 additionally depends on QUIC and ALPN.
- `test/testcase/net/http/testvector_http2.cpp` and `testcase_http.cpp` — source-level framing examples.

## 6. References
No external references are currently listed.
