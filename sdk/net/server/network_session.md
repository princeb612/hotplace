# network session

`network_session` is the server-side object that binds a socket to stream buffers and session state. It is the unit passed between the producer and consumer stages of `network_server`.

## Session state

A session owns or references:

- `netsession_t` / socket information
- `network_stream _stream` — raw received data
- `network_stream _request` — protocol-composed data
- `network_session_data` — application/session key-value state
- optional `http2_session`
- the associated `server_socket`

The object is reference-counted because the session manager, producer queue, consumer and callbacks can overlap in lifetime.

## TCP/TLS sessions

`network_session_manager::connected()` creates one `network_session` per accepted socket and stores it in `_session_map`, keyed by the event socket handle.

The typical flow is:

```text
accept
  -> session_manager.connected()
  -> network_session::connected()
  -> multiplexer.bind(session)
  -> read event
  -> session_manager.find(socket)
  -> session.produce(...)
  -> consumer
  -> session.consume(...)
```

When a socket closes, `ready_to_close()` removes the session from the manager before the multiplexer binding is released. This prevents concurrent event handling from retaining the session through the manager's normal lookup path.

## UDP and DTLS sessions

Datagram sessions are different because the listening socket is shared.

For UDP, `get_dgram_session()` maintains a session associated with the listening socket. For DTLS, `get_dgram_cookie_session()` derives a cookie from the peer address and uses a separate session object bound to that address.

```text
UDP
  listen socket
      -> dgram session
      -> peer address carried with network_stream_data

DTLS
  listen socket
      -> address-derived cookie
      -> per-peer DTLS session
      -> handshake/open
```

`network_session::udp_session_open()` and `dtls_session_open()` establish the datagram-side socket state. `dtls_session_handshake()` performs the DTLS session handshake after the per-peer session is obtained.

## Producer / consumer interface

`produce()` is the input side. It routes to `produce_stream()` or `produce_dgram()` and pushes received bytes into `_stream` while placing the session on the multi-level feedback queue when appropriate.

`consume()` is the interpretation side. It reads `_stream` through a `network_protocol_group` and puts completed messages into `_request`. The caller then consumes the resulting `network_stream_data` chain.

This separation is important: a multiplexer event is not necessarily one application message. TCP can split or combine messages, and protocol framing is therefore handled after bytes have entered the raw stream.

## Send path

`send()` sends through the session's associated server socket. `sendto()` supplies an explicit peer address for datagram operation. The session therefore exposes both connected-stream and address-oriented datagram output without making protocol framing part of the socket abstraction.

## Priority

`network_session` has a session priority used by the producer/consumer queue. Protocol parsing can also set priority on `network_stream_data`; the remaining data is retained with that priority when a message boundary falls inside a buffered item.

## Higher-level state

`get_session_data()` provides a small session-owned key/value state object. `get_http2_session()` exposes an optional HTTP/2 session object used by HTTP-layer processing. These are integrations above the generic transport/session machinery, not a requirement of every network session.

## Related tests

The HTTP/2 test vector is a useful direct illustration of the same producer/consumer model. It creates a `network_session`, feeds frames into its stream, then calls `consume()` with an `http2_protocol` before passing the resulting data to `http2_session`.

See `test/testcase/net/http/testvector_http2.cpp` and `test/testcase/net/http/testcase_http.cpp`.
