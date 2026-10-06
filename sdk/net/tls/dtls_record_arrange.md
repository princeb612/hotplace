# DTLS record arrangement

## Identity

`dtls_record_arrange` is the session-level DTLS 1.2 record reordering component. It accepts datagrams containing one or more DTLS records, groups records by the peer address, and holds records until the next expected `(epoch, sequence)` can be consumed.

It is exposed through `tls_session::get_dtls_record_arrange()` and is used by the DTLS receive path and the corresponding construction test.

## Arrangement model

```text
UDP datagram
    |
    v
dtls_record_arrange::produce()
    |
    +-- validate DTLS version and record length
    |
    +-- derive peer cookie from sockaddr
    |
    +-- extract epoch + 48-bit sequence
    |
    +-- store record in per-peer ordered pool
    |
    v
dtls_record_arrange::consume()
    |
    +-- inspect lowest stored epoch/sequence
    |
    +-- if not the expected record -> not_ready
    |
    +-- return record
    +-- advance expected position
```

The internal pool is keyed by a cookie derived from the peer address. Each peer entry maintains the current epoch, next expected sequence number, and an ordered map of stored packets.

## Reordering behavior

For example, records arriving as:

```text
epoch 0, seq 0
epoch 0, seq 2
epoch 0, seq 1
```

are consumed as:

```text
epoch 0, seq 0
epoch 0, seq 1
epoch 0, seq 2
```

Records older than the current `(epoch, sequence)` are treated as retransmissions and discarded. The per-peer packet pool is also bounded to avoid unbounded accumulation.

When a ChangeCipherSpec record is consumed, the expected epoch advances and the sequence number is reset. Otherwise the next expected sequence is incremented.

## Interface

- `produce(addr, addrlen, stream, size)` parses and queues DTLS records from a datagram.
- `consume(addr, addrlen, bin)` returns the next record when it is ready.
- `consume(addr, addrlen, epoch, seq, bin)` additionally exposes the record position.
- `make_epoch_seq()` and `get_epoch_seq()` encode/decode the 16-bit epoch and 48-bit sequence into an ordered key.

## Session relationship

```text
tls_session
    |
    +-- dtls_record_arrange
    |      +-- peer-address pool
    |      +-- epoch / sequence tracking
    |      +-- reordering
    |
    +-- dtls_record_publisher
    |
    +-- QUIC session / publisher
```

The class is concerned with **receive-side ordering**. It does not construct DTLS handshake fragments; that responsibility belongs to `dtls_record_publisher`.

## Related source and tests

- `dtls_record_arrange.hpp`
- `session/dtls_record_arrange.cpp`
- `test/testcase/tls/testcase_dtls_record_arrange.cpp`
- `test/testcase/tls/testcase_construct_dtls12_1.cpp`
- `test/testcase/tls/testcase_construct_dtls12_2.cpp`

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```
