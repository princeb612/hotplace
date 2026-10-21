## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# IP address and access-control utilities

## 1. Role

This directory provides address normalization and the `ipaddr_acl` rule engine used by network-basic callers. It evaluates whether an IPv4/IPv6 peer address matches configured allow/deny rules; it does not open sockets or automatically enforce the decision.

## 2. Data Model

### Address representation

The public API accepts textual addresses or `sockaddr_storage_t` values. `convert_addr` and `convert_sockaddr` normalize them to `ipaddr_t` while retaining family information for validation.

- When `__SIZEOF_INT128__` is defined, `ipaddr_t` is a 128-bit unsigned integer and IPv6 rules are supported.
- Otherwise, `ipaddr_t` is 32-bit and IPv6 input returns `not_supported`.
- IPv4 prefix calculations use a 32-bit mask and constrain the result to the low 32 bits.
- Range endpoints must have the same address family, and the start must not exceed the end.

This is a normalized integer-key model, not two independent IPv4 and IPv6 rule engines.

### Rule representation

A rule can represent an exact address, a CIDR prefix, or an inclusive address range, with an `allow` outcome. Exact-address rules and range-like rules are stored separately:

```text
add_rule(...)
  ├─ exact address ───────> _single_type_rule[address]
  └─ CIDR / address range -> _range_type_rule[start]
                              item.addr  = inclusive end
                              item.allow = true / false
```

CIDR is calculated as an inclusive range rather than stored as a separate rule-map type.

## 3. Behavior Model

### Whitelist and blacklist

The constructor starts in blacklist mode.

- **Blacklist mode:** unmatched addresses are allowed by default; a matching deny rule rejects, while an explicit allow rule may allow.
- **Whitelist mode:** unmatched addresses are denied by default; a matching allow rule may allow, while a deny rule rejects.

The mode determines the default for an address with no matching rule. It does not invert each rule's `allow` value.

### Matching and conflict resolution

`determine` normalizes and validates the address, initializes the result from the current mode, and checks exact and range/CIDR rules.

```text
determine(address)
  -> normalize address and validate family
  -> initialize default from blacklist/whitelist mode
  -> collect matching exact + range/CIDR outcomes
       no match           -> default
       all allow          -> allow
       all deny           -> deny
       allow and deny     -> deny (conflict is deny)
```

A more-specific allow does not automatically override a broader deny. If matching rules disagree, deny wins. The current `clear()` implementation clears `_range_type_rule` but does not clear `_single_type_rule`; it is not a complete reset of every stored rule.

### Caller enforcement

```text
server / socket caller
        │ configure rules + mode
        ▼
     ipaddr_acl
        │ determine(peer address)
        ▼
  allow / deny result
        │
        ▼
caller enforces the decision
```

The rule collection is synchronized during insertion and matching. This does not make mode changes, clearing, and server accept lifecycle coordination an atomic server-wide operation.

## 4. Relationships

- `ipaddr_acl.hpp/.cpp` — public API, normalized rule representation, and matching implementation.
- `sdk.hpp/.cpp` — SDK-facing integration.
- [Basic socket layer](../README.md) — socket abstractions and caller-side admission boundary.
- [OpenSSL backend](../openssl/README.md) and [trial backend](../trial/README.md) — backend integration points; neither makes the ACL enforce itself.
- [Network server](../../server/README.md) — higher-level accept/session orchestration.
- `test/testcase/net/basic/testcase_acl.cpp` — source-level ACL assertions; this documentation update does not claim that tests were executed.

## 5. References

No external references are currently listed.
