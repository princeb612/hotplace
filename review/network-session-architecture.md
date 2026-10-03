# Hotplace Network Session Architecture

> **Review baseline:** Revision 1096

The network layer can be viewed as a progression from platform socket primitives toward protocol-facing session objects.

```text
platform socket
      ↓
network_session
      ↓
network_stream
      ↓
network_protocol
```

Around this path are event and lifecycle components:

```text
                 multiplexer
                /           \
             epoll          IOCP
                \           /
                 session
                   │
          ┌────────┴────────┐
          ▼                 ▼
      producer           consumer
```

The platform boundary keeps Linux/Windows event mechanisms away from protocol code.

```text
OS / socket API
       ↓
I/O abstraction
       ↓
session
       ↓
protocol
```

A hotplace `network_stream` should not automatically be interpreted as a one-to-one representation of a QUIC wire stream; those are different abstraction boundaries.

### Related source / documents

- `sdk/io/system/`
- socket and multiplexer implementations
- `network_session`
- `network_stream`
- `network_protocol`
- epoll / IOCP documentation
- network server/session documentation

---

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1096                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
