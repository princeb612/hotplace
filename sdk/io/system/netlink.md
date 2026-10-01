# netlink

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

## Related source

- `sdk/io/system/netlink.hpp`
- `sdk/io/system/netlink.cpp`

## Platform scope

Do not treat netlink as a cross-platform backend of the generic multiplexer/socket APIs. Its purpose is direct Linux system integration.
