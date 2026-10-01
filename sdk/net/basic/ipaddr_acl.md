# IP Address ACL

`ipaddr_acl` provides address-based access control for network components.

## Supported rules

The implementation accepts:

- single IPv4/IPv6 addresses
- CIDR addresses
- address ranges
- allow/deny rules
- whitelist and blacklist modes

Address conversion supports the platform's available integer width; IPv6 uses the project's wide integer representation when `__SIZEOF_INT128__` is available.

## Matching model

```text
address text / sockaddr
        ↓
convert_addr / convert_sockaddr
        ↓
normalized address
        ↓
single / CIDR / range rule lookup
        ↓
allow / deny result
```

The rule collections are protected by a critical section because ACL configuration and determination share the internal maps.

## Tests

`test/testcase/net/basic/testcase_acl.cpp` covers address rules and determination behavior.

## Source

- `ipaddr_acl.hpp/.cpp`
- `sdk.hpp/.cpp`
