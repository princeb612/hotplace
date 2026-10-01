# network server model

`network_server` is the execution layer that connects the OS/network multiplexer with hotplace's socket, session, stream, protocol and callback layers.

The implementation is organized around three processing paths:

```text
network multiplexer
    |
    +-- accept ------------------> network_session
    |                               |
    |                               +-- socket
    |
    +-- read/dgram -> producer --> network_session::produce
    |                               |
    |                               +-- network_stream
    |
    +-- consumer ----------------> network_session::consume
                                    |
                                    +-- network_stream::read
                                    |      +-- network_protocol_group
                                    |      +-- network_protocol
                                    |
                                    +-- user callback
```

## Multiplexer boundary

The server selects the platform multiplexer at compile time:

- Linux: `multiplexer_epoll`
- Windows: `multiplexer_iocp`
- macOS: `multiplexer_kqueue` is referenced by the class, but the existing server README/source marks kqueue support as not implemented.

`network_server::open()` creates a `network_multiplexer_context_t` containing the server socket, session manager, protocol group, event queue, callback and thread-control objects.

## Processing threads

The source separates the work into distinct loops rather than doing protocol interpretation directly inside the multiplexer callback.

```text
accept_thread
  -> accept socket
  -> optional accept-control callback
  -> optional TLS accept queue
  -> session_accepted

producer_thread / producer_routine
  -> consume multiplexer read/dgram event
  -> find/create network_session
  -> session.produce(...)
  -> enqueue session by priority

consumer_thread / consumer_routine
  -> dequeue network_session
  -> session.consume(protocol_group, ...)
  -> dispatch completed data to callback
```

For TLS server sockets, the accept path is split again so that the TLS handshake can be handled by one or more `tls_accept_thread` workers before the session is attached to the multiplexer.

## Configuration

`server_conf` stores concurrency and buffer settings through `t_key_value`:

- `serverconf_concurrent_event`
- `serverconf_concurrent_tls_accept`
- `serverconf_concurrent_network`
- `serverconf_concurrent_consume`
- TCP/UDP buffer sizes
- HTTP/HTTPS and HTTP/1.1/2/3 flags used by higher server layers

The default implementation uses event concurrency `1024`, TLS accept concurrency `1`, producer concurrency `2`, and consumer concurrency `2`.

## Callback boundary

After `network_session::consume()` produces interpreted data, `consumer_routine()` builds the callback array. The important entries are the socket, data pointer, data size, session and UDP peer address. The event type distinguishes stream reads from datagram reads and connection events.

This makes `network_server` a transport/session dispatcher rather than an HTTP implementation. HTTP/1, HTTP/2 and HTTP/3 belong to `sdk/net/http/` and use this layer underneath.

## Lifecycle

The public lifecycle is intentionally split:

```text
open
  -> tls_accept_loop_run (TLS server when needed)
  -> event_loop_run
  -> consumer_loop_run
  ...
  -> event_loop_break / consumer_loop_break / tls_accept_loop_break
  -> close
```

`close()` is responsible for stopping the worker groups, clearing protocol registrations and closing the multiplexer context.

## Related modules

- `sdk/net/basic/` — concrete client/server sockets and TLS/DTLS socket adapters
- `sdk/net/server/network_session.*` — per-connection and datagram session state
- `sdk/net/server/network_stream.*` — raw/composed stream buffering
- `sdk/net/server/network_protocol.*` — protocol identification and message framing
- `sdk/net/http/` — HTTP protocol/server layer
- `sdk/net/tls/` — TLS/DTLS/QUIC protocol and cryptographic processing
