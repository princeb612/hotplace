## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# IP Address ACL

## 1. Role

`ipaddr_acl` provides address-based access control for network components.

## 2. Model

### Supported rules

The implementation accepts:

- single IPv4/IPv6 addresses
- CIDR addresses
- address ranges
- allow/deny rules
- whitelist and blacklist modes

Address conversion supports the platform's available integer width; IPv6 uses the project's wide integer representation when `__SIZEOF_INT128__` is available.

### Matching model

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

### Source

- `ipaddr_acl.hpp/.cpp`
- `sdk.hpp/.cpp`

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

### Tests

`test/testcase/net/basic/testcase_acl.cpp` covers address rules and determination behavior.

## 5. Relationships

Related implementation areas and protocol boundaries are recorded here where identified.

## 6. References

Source references and related documents are retained here where available.
