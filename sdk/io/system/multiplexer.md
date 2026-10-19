## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# multiplexer

## 1. Role

The multiplexer layer abstracts platform event notification for asynchronous I/O.

## 2. Model

### Architecture

```text
higher-level I/O / network
          |
          v
     multiplexer
          |
   +------+------+ 
   |             |
 epoll          IOCP
 Linux         Windows
```

`multiplexer_controller` provides the control path while platform implementations provide the actual event mechanism.

### Implemented backends

- Linux: `multiplexer_epoll.cpp`
- Windows: `multiplexer_iocp.cpp`

The source declares the broader multiplexer abstraction, but this revision should not be read as claiming a complete `kqueue` backend; the relevant enum/declarations do not represent an implemented backend.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

### Related area

`sdk/net/server/` consumes the multiplexer layer as part of the server/session flow.

## 6. References

### Related source

- `sdk/io/system/multiplexer.hpp`
- `sdk/io/system/multiplexer_controller.cpp`
- `sdk/io/system/multiplexer_epoll.cpp`
- `sdk/io/system/multiplexer_iocp.cpp`
