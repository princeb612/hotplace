# network stream and protocol interpretation

`network_stream` and `network_protocol` form the framing boundary between arbitrary network reads and application-level messages.

## Raw stream

`network_stream::produce()` copies received bytes into a `network_stream_data` node and appends it to a protected queue. A node contains:

- byte buffer and size
- optional UDP peer address
- priority
- linked-list next pointer
- reference counting

`consume()` detaches the queued nodes as a chain, allowing the producer side to continue without keeping the consumer's traversal lock.

```text
socket read
   ↓
network_stream::produce
   ↓
network_stream_data -> network_stream_data -> ...
   ↓
network_stream::consume
```

## Protocol group

`network_protocol_group` owns a map from `protocol_id()` to `network_protocol`. It provides three useful operations:

- register/remove protocol interpreters
- find a protocol by identifier
- inspect buffered bytes and select the protocol whose `is_kind_of()` accepts them

Protocol objects are reference-counted while registered or temporarily selected.

`is_kind_of()` may return `more_data`, which is important when the current network buffer does not contain enough bytes to identify a protocol yet.

## Protocol interpreter

A `network_protocol` supplies the protocol-specific framing decision:

```text
is_kind_of(bytes)
      ↓
protocol selected
      ↓
read_stream(bytes)
      ↓
protocol_state_t
```

The state can describe a completed message or a rejected/invalid/oversized input (`forged`, `crash`, `large`). A protocol may also assign a priority to the resulting message and expose a packet-size constraint.

`use_alpn()` is available for protocols whose selection is associated with ALPN; the generic base implementation returns false. HTTP/3 is one example of a higher-level protocol where ALPN information matters.

## Framing across multiple reads

`network_stream::do_writep()` is the central framing loop. It concatenates queued `network_stream_data` into a temporary `basic_stream`, asks the protocol group to identify a protocol, and calls `read_stream()`.

When the protocol reports `complete`, only the identified message is moved into the target stream. Any remaining bytes stay queued and cause `more_data` processing to repeat.

Conceptually:

```text
read #1        read #2
  |              |
  +---- raw stream queue ----+
                             ↓
                     protocol grouping
                             ↓
                       read_stream()
                       /           \
                  complete       more_data
                     |                |
                target stream     keep bytes
                     |                |
                     +-------<--------+
```

This is why the network server can treat TCP reads as arbitrary byte chunks rather than assuming one read equals one request.

## Invalid input handling

For `forged`, `crash` and `large`, the current implementation discards the queued stream data instead of leaving an invalid message in the processing path. A protocol implementation therefore controls both message boundaries and the basic failure state used by the generic stream layer.

## Write/copy behavior

`network_stream::write()` copies queued data into another stream. With an empty protocol group it performs a direct copy. With protocol interpreters it performs framing and may emit one or more complete messages.

This same mechanism is useful outside the full `network_server`: the HTTP/2 test vector directly feeds bytes to a session stream and invokes `session.consume()` with an `http2_protocol`.

## Related modules

- `sdk/net/http/http1/` and `sdk/net/http/http2/` — concrete protocol interpreters using this boundary
- `sdk/net/http/http3/` — HTTP/3 processing and QUIC/ALPN integration
- `sdk/net/basic/` — byte transport and socket lifecycle below this layer
