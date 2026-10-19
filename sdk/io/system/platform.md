## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# platform

## 1. Role

The remaining files in `sdk/io/system` provide platform-specific support around the common I/O primitives.

```text
                 sdk/io/system
                       |
          +------------+------------+
          |                         |
       common                  platform code
          |                         |
 socket / multiplexer       Linux / Windows APIs
```

Representative platform files include:

- Linux epoll and netlink support
- Windows IOCP and Winsock support
- Windows Registry support
- PE/Windows native structures

The directory therefore acts as a boundary: portable SDK abstractions are kept above direct operating-system APIs, while platform code remains localized here.

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

### Related source

- `sdk/io/system/linux/`
- `sdk/io/system/windows/`
- `sdk/io/system/multiplexer.hpp`
- `sdk/io/system/socket.hpp`
