## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# IP address and access-control utilities

## 1. Role

This directory provides address normalization and the `ipaddr_acl` rule engine used by network-basic callers. It evaluates whether an IPv4/IPv6 peer address matches configured allow/deny rules; it does not open sockets or automatically enforce the decision.

## 2. Data Model

### Address representation

The public API accepts textual addresses or `sockaddr_storage_t` values. The normalized key is `ipaddr_t`; family information is retained for validation so IPv4 is not accidentally treated as IPv6.

- When `__SIZEOF_INT128__` is defined, `ipaddr_t` is a 128-bit unsigned integer and IPv6 rules are supported.
- Otherwise, `ipaddr_t` is 32-bit and IPv6 input returns `not_supported`.
- IPv4 prefix calculations use a 32-bit mask and constrain the result to the low 32 bits.
- Range endpoints must have the same address family, and the start must not exceed the end.

This is a normalized integer-key model, not two independent IPv4 and IPv6 rule engines.

### Rule representation

A rule can represent an exact address, a CIDR prefix, or an inclusive address range, with an `allow` outcome. Exact-address rules and range-like rules are stored separately:

- `_single_type_rule` is keyed by the normalized exact address.
- `_range_type_rule` is keyed by the inclusive start address; its value retains the inclusive end in `item.addr` and the allow/deny outcome in `item.allow`.
- CIDR is represented as an inclusive range rather than as a separate rule-map type.

## 3. Behavior Model

### Address normalization and rule insertion

```text
text address / sockaddr_storage_t
              |
              v
    convert_addr / convert_sockaddr
              |
              v
       ipaddr_t + family
              |
              v
        validate input
              |
              v
  exact / CIDR / inclusive range rule
              |
              v
 _single_type_rule / _range_type_rule
```

CIDR input is converted into an inclusive start/end interval before storage. Address-family checks and integer-width support described in Data Model constrain which inputs can be represented.

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

### Practical use: configure rules and ask for a decision

The ACL testcase combines exact addresses, a CIDR prefix, and an inclusive range, then evaluates the same rule set in both modes:

```cpp
ipaddr_acl acl;
acl.add_rule("127.0.0.1", true);          // exact allow
acl.add_rule("10.20.13.25", 24, false);   // deny the /24 range
acl.add_rule("10.20.1.25", "10.20.2.10", false);

acl.setmode(ipaddr_acl_t::whitelist);
bool allowed = false;
return_t ret = acl.determine("127.0.0.1", allowed);
if (errorcode_t::success == ret) {
    // Caller decides whether to admit or reject the peer.
}
```

The rule engine only returns a decision; it does not close a socket or reject a server session. The testcase also switches to blacklist mode and checks IPv6 loopback/interval behavior when IPv6 support is compiled in. Because conflicting matching rules resolve to deny, do not assume a more-specific allow overrides a broader deny.

Source: [testcase_acl.cpp](../../../../test/testcase/net/basic/testcase_acl.cpp).

## 5. Relationships
- `ipaddr_acl.hpp/.cpp` — public API, normalized rule representation, and matching implementation.
- `sdk.hpp/.cpp` — SDK-facing integration.
- [Basic socket layer](../README.md) — socket abstractions and caller-side admission boundary.
- [OpenSSL backend](../openssl/README.md) and [trial backend](../trial/README.md) — backend integration points; neither makes the ACL enforce itself.
- [Network server](../../server/README.md) — higher-level accept/session orchestration.
- `test/testcase/net/basic/testcase_acl.cpp` — source-level ACL assertions; this documentation update does not claim that tests were executed.

## 6. References
No external references are currently listed.
