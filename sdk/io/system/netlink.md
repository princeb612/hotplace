## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# netlink

## 1. Role

`netlink.hpp` / `netlink.cpp` contains Linux netlink support used to communicate with kernel networking facilities.

```text
application
    |
    v
sdk/io/system/netlink
    |
    v
Linux netlink socket
    |
    v
kernel networking state
```

This is a Linux-specific integration layer, not a portable socket abstraction.

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

### Platform scope

Do not treat netlink as a cross-platform backend of the generic multiplexer/socket APIs. Its purpose is direct Linux system integration.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

### Related source

- `sdk/io/system/netlink.hpp`
- `sdk/io/system/netlink.cpp`
